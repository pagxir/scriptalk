#include "stdafx.h"
#include "resource.h"
#include <windowsx.h>
#include <commctrl.h>
#include <shellapi.h>

#include <map>
#include <vector>
#include <string>

#define MAX_LOADSTRING 100

HWND hMainWnd;
HINSTANCE hInst;
BOOL bBlackWhite = FALSE;
HICON g_hBlackIcon = NULL, g_hWhiteIcon = NULL;

TCHAR szTitle[MAX_LOADSTRING];
TCHAR szWindowClass[MAX_LOADSTRING];

ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK	About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
	MSG msg;
	HACCEL hAccelTable;
	
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_MINIXMPPCLIENT, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);
	
	InitCommonControls();
	if (!InitInstance (hInstance, nCmdShow)) 
		return FALSE;

	hAccelTable = LoadAccelerators(hInstance, (LPCTSTR)IDC_MINIXMPPCLIENT);
	
	while (GetMessage(&msg, NULL, 0, 0)) {
		if (!IsDialogMessage(hMainWnd, &msg)) {
			if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
	}
	
	return msg.wParam;
}

ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;
	
	wcex.cbSize = sizeof(WNDCLASSEX); 
	
	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= (WNDPROC)WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, (LPCTSTR)IDI_MINIXMPPCLIENT);
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_BTNFACE+1);
	wcex.lpszMenuName	= (LPCSTR)IDC_MINIXMPPCLIENT;
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, (LPCTSTR)IDI_SMALL);
	
	return RegisterClassEx(&wcex);
}

HWND CreateHideWnd()
{
	HWND hWnd = NULL;

	WNDCLASSEX wcex;
	wcex.cbSize = sizeof(WNDCLASSEX); 
	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= (WNDPROC)DefWindowProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInst;
	wcex.hIcon			= NULL;
	wcex.hCursor		= NULL;
	wcex.hbrBackground	= NULL;
	wcex.lpszMenuName	= NULL;
	wcex.lpszClassName	= "hide wnd class";
	wcex.hIconSm		= LoadIcon(wcex.hInstance, (LPCTSTR)IDI_SMALL);
	if (!RegisterClassEx(&wcex))
		return NULL;
	hWnd = CreateWindow("hide wnd class", NULL, 0,
		0, 0, 0, 0, NULL, NULL, hInst, NULL);
	return hWnd;
}

HWND GetHideWnd()
{
	static HWND _hwnd_hide = CreateHideWnd();
	return _hwnd_hide;
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	HWND hWnd;
	
	hInst = hInstance;

	int scrWidth = GetSystemMetrics(SM_CXSCREEN);
	
	DWORD wStyle = WS_TABSTOP|WS_POPUPWINDOW|WS_MINIMIZEBOX;
	wStyle |= (WS_MAXIMIZEBOX|WS_CAPTION|WS_THICKFRAME);

	hWnd = CreateWindow(szWindowClass, szTitle, wStyle,
		scrWidth-260, 60, 200, 600, GetHideWnd(), NULL, hInstance, NULL);
	
	if (hWnd == NULL)
		return FALSE;
	
	hMainWnd = hWnd;
	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);
	
	return TRUE;
}

void CreateLoginBox(HWND hWnd)
{
	RECT Rect;
	GetClientRect(hWnd, &Rect);

	int PadWidth  = -50;
	DWORD UsrWidth  = 150;
	DWORD UsrHeight = GetSystemMetrics(SM_CYMENU);
	
	HWND hUsrName = CreateWindowEx(WS_EX_CLIENTEDGE, "Edit", "dupit8@gmail.com", 
		WS_TABSTOP|WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,
		(Rect.right-UsrWidth)/2, (Rect.bottom-UsrHeight+PadWidth)/2, UsrWidth, UsrHeight,
		hWnd, HMENU(0x1982), NULL, NULL);
	SetWindowFont(hUsrName, GetStockObject(SYSTEM_FIXED_FONT), FALSE);
	PadWidth += GetSystemMetrics(SM_CYMENU)*3.3;
	HWND hPassword = CreateWindowEx(WS_EX_CLIENTEDGE, "Edit", "pagx@china.com.cn", 
		WS_TABSTOP|WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL|ES_PASSWORD,
		(Rect.right-UsrWidth)/2, (Rect.bottom-UsrHeight+PadWidth)/2, UsrWidth, UsrHeight,
		hWnd, HMENU(0x1983), NULL, NULL);
	SetWindowFont(hPassword, GetStockObject(SYSTEM_FIXED_FONT), FALSE);
	UsrWidth = 100;
	PadWidth += GetSystemMetrics(SM_CYMENU)*4;
	HWND hCtrlLogin = CreateWindow("Button", "Login", WS_TABSTOP|WS_CHILD|WS_VISIBLE,
		(Rect.right-UsrWidth)/2, (Rect.bottom-UsrHeight+PadWidth)/2, UsrWidth, UsrHeight,
		hWnd, HMENU(IDM_LOGIN), NULL, NULL);

}

BOOL DestroyLoginBox(HWND hWnd)
{
	DestroyWindow(GetDlgItem(hWnd, 0x1982));
	DestroyWindow(GetDlgItem(hWnd, 0x1983));
	DestroyWindow(GetDlgItem(hWnd, IDM_LOGIN));
	return TRUE;
}

int XmppClient(const char *jid, const char *passwd);

BOOL CreateXmppSecion(HWND hWnd)
{
	char UsrName[1024], Password[1024];
	GetDlgItemText(hWnd, 0x1982, UsrName, sizeof(UsrName));
	GetDlgItemText(hWnd, 0x1983, Password, sizeof(Password));
	SetTimer(hWnd, 0x2009, 1000, NULL);
	XmppClient(UsrName, Password);
	return TRUE;
}

BOOL CreateRosterView(HWND hWndParent)
{
	RECT Rect;
	GetClientRect(hWndParent, &Rect);
	HWND hWndTree = CreateWindow(TEXT("SysTreeView32"), TEXT("Simple"),
		WS_BORDER|WS_CHILD|WS_VISIBLE|TVS_TRACKSELECT|TVS_HASBUTTONS|TVS_HASLINES|TVS_LINESATROOT|TVS_SHOWSELALWAYS,
		0, 0, Rect.right, Rect.bottom, hWndParent, HMENU(0x2009), hInst, 0);
#if 0
	TVINSERTSTRUCT tvInst;
	tvInst.item.mask = TVIF_TEXT;
	tvInst.hInsertAfter = TVI_LAST;
	tvInst.hParent = NULL;
	tvInst.item.pszText = TEXT("3D object list");
	
	HTREEITEM hNode1 = (HTREEITEM)SendMessage(hWndTree,
		TVM_INSERTITEM,	0, (LPARAM)&tvInst);
	
	tvInst.item.pszText = TEXT("Material list");
	
	HTREEITEM hNode2 = (HTREEITEM)SendMessage(hWndTree,
		TVM_INSERTITEM,	0, (LPARAM)&tvInst);
	
	tvInst.item.pszText = TEXT("Light list");
	
	HTREEITEM hNode3 = (HTREEITEM)SendMessage(hWndTree,
		TVM_INSERTITEM,	0, (LPARAM)&tvInst);
	
	tvInst.item.pszText = TEXT("child1");
	tvInst.hParent = hNode1;
	
	HTREEITEM hChild1 = (HTREEITEM)SendMessage(hWndTree, 
		TVM_INSERTITEM,	0, (LPARAM)&tvInst);
	
	tvInst.item.pszText = TEXT("child2");
	
	HTREEITEM hChild2 = (HTREEITEM)SendMessage(hWndTree,
		TVM_INSERTITEM,	0, (LPARAM)&tvInst);
#endif	
	return TRUE;
}

int xmpp_open_presence();
const char *xmpp_read_presence();
int xmpp_close_presence();

struct TreeViewItem{BOOL bRemoved; LRESULT lResult;};
static std::map<std::string, TreeViewItem> g_presence_list;

BOOL UpdateOnlineUser(HWND hWnd)
{
	const char *presence;
	HWND hWndTree = GetDlgItem(hWnd, 0x2009);

	std::map<std::string, TreeViewItem>::iterator iter;
	iter = g_presence_list.begin();
	while (iter != g_presence_list.end()){
		iter->second.bRemoved = TRUE;
		++iter;
	}

	xmpp_open_presence();
	while (presence=xmpp_read_presence()) {
		TVINSERTSTRUCT tvInst;
		tvInst.item.mask = TVIF_TEXT;
		tvInst.hInsertAfter = TVI_LAST;
		tvInst.hParent = NULL;
		tvInst.item.pszText = (char*)presence;
		
		if (g_presence_list.find(presence)
			== g_presence_list.end()) {
			LRESULT lResult = SendMessage(hWndTree, TVM_INSERTITEM, 0, (LPARAM)&tvInst);
			g_presence_list[presence].lResult = lResult;
		}
		g_presence_list[presence].bRemoved = FALSE;
	}
	xmpp_close_presence();

	std::vector<std::string> remove_vector;
	iter = g_presence_list.begin();
	while (iter != g_presence_list.end()) {
		if (iter->second.bRemoved) {
			remove_vector.push_back(iter->first);
			TreeView_DeleteItem(hWndTree, iter->second.lResult);
		}
		++iter;
	}
	int i;
	for (i=0; i<remove_vector.size(); i++)
		g_presence_list.erase(remove_vector[i]);
	return TRUE;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	NOTIFYICONDATA data;
	TCHAR szHello[MAX_LOADSTRING];
	LoadString(hInst, IDS_HELLO, szHello, MAX_LOADSTRING);
	
	switch (message) 
	{
		case WM_CREATE:
			g_hBlackIcon = LoadIcon(hInst, (const char *)IDI_BLACK_ICON);
			g_hWhiteIcon = LoadIcon(hInst, (const char *)IDI_WHITE_ICON);
			
			data.cbSize = sizeof(data);
			data.hIcon  = g_hBlackIcon;
			data.hWnd   = hWnd;
			strcpy(data.szTip, "Hello World!");
			data.uCallbackMessage = WM_COMMAND;
			data.uFlags = NIF_ICON|NIF_TIP|NIF_MESSAGE|NIF_INFO;
			data.uID    = 0x2009;
			
			data.dwState = 0;
			data.dwStateMask = NIS_HIDDEN;
			strcpy(data.szInfo, "Hello X!");
			data.uVersion = 1;
			data.dwInfoFlags = NIIF_INFO;
			strcpy(data.szInfoTitle, "google");
			
			Shell_NotifyIcon(NIM_ADD, &data);
			//SetTimer(hWnd, 0x1992, 500, NULL);
			CreateLoginBox(hWnd);
			break;
		case WM_SIZE:
			if (wParam != SIZE_MINIMIZED)
				MoveWindow(GetDlgItem(hWnd, 0x2009), 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE);
			else
				ShowWindow(hWnd, SW_HIDE);
			break;
		case WM_TIMER:		
			data.cbSize = sizeof(data);
			data.hIcon  = bBlackWhite?g_hBlackIcon:g_hWhiteIcon;
			data.hWnd   = hWnd;
			strcpy(data.szTip, "Hello World!");
			data.uCallbackMessage = WM_COMMAND;
			data.uFlags = NIF_ICON|NIF_TIP|NIF_MESSAGE;//|NIF_INFO;
			data.uID    = 0x2009;
			data.dwState = 0;
			data.dwStateMask = 0;
			strcpy(data.szInfo, "Hello X!");
			data.uVersion = 12000;
			data.dwInfoFlags = NIIF_NONE;
			strcpy(data.szInfoTitle, "google");
			Shell_NotifyIcon(NIM_MODIFY, &data);
			bBlackWhite = !bBlackWhite;			
			UpdateOnlineUser(hWnd);
			break;
		case WM_NOTIFY:
			if (wParam == 0x2009) {
				POINT pt;
				HMENU hMenu;
				HTREEITEM hTreeItem = NULL;
				TVHITTESTINFO tvhittestinfo;
				NM_TREEVIEW* pNMTreeView = (NM_TREEVIEW*)lParam;
				switch (pNMTreeView->hdr.code)
				{
					case NM_RCLICK:
						GetCursorPos(&pt);
						tvhittestinfo.pt = pt;
						tvhittestinfo.flags = 0;
						tvhittestinfo.hItem = NULL;
						ScreenToClient(GetDlgItem(hWnd, 0x2009), &tvhittestinfo.pt);
						hTreeItem = TreeView_HitTest(GetDlgItem(hWnd, 0x2009), &tvhittestinfo);
						if (hTreeItem != NULL) {
							TreeView_SelectItem(GetDlgItem(hWnd, 0x2009), hTreeItem);
							hMenu = LoadMenu(hInst, (char*)IDC_CONTEXT);
							TrackPopupMenu(GetSubMenu(hMenu, 0), TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
							DestroyMenu(hMenu);
						}
						break;
					case TVN_SELCHANGING:
						//MessageBox(hWnd, "", "2", MB_OK);
						break;
					case TVN_SELCHANGED:
						//MessageBox(hWnd, "", "3", MB_OK);
						break;
				}
			}
			break;
		case WM_COMMAND:
			wmId    = LOWORD(wParam); 
			wmEvent = HIWORD(wParam); 
			switch (wmId)
			{
				case IDM_LOGIN:
					CreateXmppSecion(hWnd);
					DestroyLoginBox(hWnd);
					CreateRosterView(hWnd);
					break;
				case IDM_FIVE_CHESS:
					{
						HTREEITEM hTreeItem = NULL;
						HWND hTreeView = GetDlgItem(hWnd, 0x2009);
						hTreeItem = TreeView_GetSelection(hTreeView);
						if (hTreeItem != NULL) {
							TV_ITEM tvItem;
							char buf[1024];
							tvItem.mask = TVIF_TEXT/*TVIF_HANDLE|*/;
							tvItem.hItem = hTreeItem;
							tvItem.pszText = buf;
							tvItem.cchTextMax = sizeof(buf);
							TreeView_GetItem(hTreeView, &tvItem);
							MessageBox(hWnd, tvItem.pszText, "Îå×ÓÆå", MB_OK);
						}
					}
					break;
				case IDM_ABOUT:
					DialogBox(hInst, (LPCTSTR)IDD_ABOUTBOX, hWnd, (DLGPROC)About);
					break;
				case IDM_EXIT:
					DestroyWindow(hWnd);
					break;
				case 0x2009:
					switch (lParam)
					{
						case WM_LBUTTONUP:
#if 0
							SetForegroundWindow(hWnd);
							BringWindowToTop(hWnd);
#endif
							if (!IsWindowVisible(hWnd))
								ShowWindow(hWnd, SW_RESTORE);
							SwitchToThisWindow(hWnd, TRUE);
							//SetActiveWindow(hWnd);
							break;
					}					
					break;
				default:					
					return DefWindowProc(hWnd, message, wParam, lParam);
			}
			break;
		case WM_DESTROY:
			data.cbSize = sizeof(data);
			data.hIcon  = bBlackWhite?g_hBlackIcon:g_hWhiteIcon;
			data.hWnd   = hWnd;
			strcpy(data.szTip, "Hello World!");
			data.uCallbackMessage = WM_COMMAND;
			data.uFlags = NIF_ICON|NIF_TIP|NIF_MESSAGE;
			data.uID    = 0x2009;
			
			data.dwState = 0;
			data.dwStateMask = 0;
			strcpy(data.szInfo, "Hello X!");
			data.uVersion = 12000;
			data.dwInfoFlags = NIIF_INFO;
			strcpy(data.szInfoTitle, "google");
			
			Shell_NotifyIcon(NIM_DELETE, &data);
			PostQuitMessage(0);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

LRESULT CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	RECT Rect;
	int w, h, x, y;

	switch (message)
	{
	case WM_INITDIALOG:
		GetClientRect(hDlg, &Rect);
		w = Rect.right-Rect.left;
		h = Rect.bottom-Rect.top; 
		x = GetSystemMetrics(SM_CXFULLSCREEN)-w;
		y = GetSystemMetrics(SM_CYFULLSCREEN)+GetSystemMetrics(SM_CYMENU)-h;
		MoveWindow(hDlg, x, y, w, h, FALSE);				
		AnimateWindow(hDlg, 500, AW_VER_NEGATIVE);
		return TRUE;
		
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
			EndDialog(hDlg, LOWORD(wParam));
			return TRUE;
		}
		break;
	}
    return FALSE;
}
