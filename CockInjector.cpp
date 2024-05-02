// CockInjector.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "CockInjector.h"
#include <vector>
#include <string>
#include <tlhelp32.h>
#include <CommCtrl.h>
#include <codecvt>
#include <locale>
#include <cwchar>
#include <iostream>

#define MAX_LOADSTRING 100
// Show a table of all running processes, including a column for their PID.
#define IDT_REFRESHTABLE 1
#define IDB_INJECT 1

FILE *f;

HWND hInjectButton;
HWND hListView;

LPVOID GetModuleBaseAddress(DWORD procId, const wchar_t *modName)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!_wcsicmp(modEntry.szModule, modName))
                {
                    CloseHandle(hSnap);
                    return modEntry.modBaseAddr;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return NULL;
}

bool InjectDLL(DWORD processID, const char *dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL)
    {
        return false;
    }

    size_t pathLen = strlen(dllPath) + 1;
    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (pDllPath == NULL)
    {
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pDllPath, dllPath, pathLen, NULL))
    {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPVOID pLoadLibrary = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (pLoadLibrary == NULL)
    {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pDllPath, 0, NULL);
    if (hThread == NULL)
    {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return true;
}

int GetSelectedProcess(HWND hListView)
{
    int iSelected = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
    if (iSelected == -1)
        return -1;

    WCHAR szProcessID[256];
    ListView_GetItemText(hListView, iSelected, 0, szProcessID, sizeof(szProcessID));

    return static_cast<int>(std::wcstol(szProcessID, nullptr, 10));
}

BYTE ContainsCockByte(DWORD pid)
{
    HANDLE hHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hHandle)
    {
        std::cout << "nohandle\n";
        return false;
    }

    LPVOID baseAddress = GetModuleBaseAddress(pid, L"rs2client.exe");
    uintptr_t remotePointerAddress;
    SIZE_T bytesRead;

    if (!ReadProcessMemory(hHandle, (void *)((uintptr_t)baseAddress + (uintptr_t)0xD40500), &remotePointerAddress, sizeof(remotePointerAddress), &bytesRead))
    {
        std::cout << "Failed to read memory. Error: " << GetLastError() << std::endl;
        CloseHandle(hHandle);
        return 8;
    }

    std::cout << "Pointer address read: " << std::hex << remotePointerAddress << std::endl;

    BYTE pointedValue;
    if (!ReadProcessMemory(hHandle, (void *)(remotePointerAddress + 0x100), &pointedValue, sizeof(pointedValue), &bytesRead))
    {
        std::cerr << "Failed to read memory at pointed address. Error: " << GetLastError() << std::endl;
        CloseHandle(hHandle);
        return 9;
    }

    std::cout << "Value at pointer address: " << std::hex << pointedValue << std::endl;

    return pointedValue;
}

void ShowProcessTable()
{
    ListView_DeleteAllItems(hListView);

    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);
        return;
    }

    std::vector<std::wstring> processIDStrings;

    do
    {
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &pe32.szExeFile[0], -1, NULL, 0, NULL, NULL);
        std::string str(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &pe32.szExeFile[0], -1, &str[0], size_needed, NULL, NULL);
        if (!str.contains("rs2client"))
            continue;

        processIDStrings.push_back(std::to_wstring(pe32.th32ProcessID));

        LVITEM lvi = {0};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = ListView_GetItemCount(hListView);
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(processIDStrings.back().c_str());
        ListView_InsertItem(hListView, &lvi);

        lvi.iSubItem = 1;
        lvi.pszText = pe32.szExeFile;
        ListView_SetItem(hListView, &lvi);

        int cb = ContainsCockByte(pe32.th32ProcessID);
        std::wstring wstr = std::to_wstring(cb);
        wchar_t *lpwstr = new wchar_t[wstr.length() + 1];
        wcscpy(lpwstr, wstr.c_str());

        lvi.iSubItem = 2;
        lvi.pszText = lpwstr;
        ListView_SetItem(hListView, &lvi);

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}
// Global Variables:
HINSTANCE hInst;                     // current instance
WCHAR szTitle[MAX_LOADSTRING];       // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING]; // the main window class name

// Forward declarations of functions included in this code module:
ATOM MyRegisterClass(HINSTANCE hInstance);
BOOL InitInstance(HINSTANCE, int);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                      _In_opt_ HINSTANCE hPrevInstance,
                      _In_ LPWSTR lpCmdLine,
                      _In_ int nCmdShow)
{
/*  AllocConsole();
    FILE *f;
    freopen_s(&f, "CONOUT$", "w", stdout);
*/

    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Place code here.

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_COCKINJECTOR, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance(hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_COCKINJECTOR));
    ShowProcessTable();

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
/*
    fclose(f);
    FreeConsole();
*/
    return (int)msg.wParam;
}

//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_COCKINJECTOR));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_COCKINJECTOR);
    wcex.lpszClassName = szWindowClass;
    wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    hInst = hInstance; // Store instance handle in our global variable

    HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
                              CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

    if (!hWnd)
    {
        return FALSE;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CLOSE:
        KillTimer(hWnd, IDT_REFRESHTABLE);
        DestroyWindow(hWnd);
        TerminateProcess(GetCurrentProcess(), 0);
        break;
    case WM_TIMER:
        if (wParam == IDT_REFRESHTABLE)
        {
            ShowProcessTable();
        }
        break;
    case WM_CREATE:
    {
        SetTimer(hWnd, IDT_REFRESHTABLE, 2000, NULL);
        // Create the ListView control
        hListView = CreateWindow(WC_LISTVIEW, L"",
                                 WS_CHILD | WS_VISIBLE | LVS_REPORT,
                                 0, 0, 300, 200, // Adjust size and position as needed
                                 hWnd, NULL, hInst, NULL);

        // Add columns to the ListView
        LVCOLUMN lvc;
        lvc.mask = LVCF_TEXT | LVCF_WIDTH;
        lvc.cx = 100; // Adjust column width as needed

        lvc.pszText = (wchar_t *)L"Process ID";
        ListView_InsertColumn(hListView, 0, &lvc);

        lvc.pszText = (wchar_t *)L"Process Name";
        ListView_InsertColumn(hListView, 1, &lvc);

        lvc.pszText = (wchar_t *)L"Cockbyte";
        ListView_InsertColumn(hListView, 2, &lvc);

        hInjectButton = CreateWindow(L"button", L"Inject",
                                     WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                     0, 250, 100, 30, // Adjust position and size as needed
                                     hWnd, (HMENU)IDB_INJECT, hInst, NULL);
        ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT);
    }
    break;
    case WM_COMMAND:
        int wmId = LOWORD(wParam);
        if (wmId == IDB_INJECT)
        {
            int processID = GetSelectedProcess(hListView);
            if (processID != -1)
            {
                // Get the current directory
                char currentDirectory[MAX_PATH];
                GetCurrentDirectoryA(MAX_PATH, currentDirectory);

                // Append "\\COCKBOT.dll" to the current directory
                std::string dllPath = std::string(currentDirectory) + "\\COCKBOT.dll";

                InjectDLL(processID, dllPath.c_str());
            }
        }
    }
    return DefWindowProc(hWnd, message, wParam, lParam);
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
