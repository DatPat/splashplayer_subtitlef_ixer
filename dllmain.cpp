#include <Windows.h>
#include <TlHelp32.h>
#include <intrin.h>

typedef int (__cdecl* Type_InitSubtitleFont)( wchar_t *Str, int, int, int, int, int, int, int, int );
Type_InitSubtitleFont pInitSubtitleFont;

int __cdecl hkInitSubtitleFont( wchar_t *Str, int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8 ) // D3D12
{
	int Len = wcslen( Str );
	
	int SkipIndex = 0;
	
	for( size_t i = 0, j = 7; i < Len && j > 0; i++ )
	{
		if( Str[i] == ',' )
		{
			if( j < 2 )
			{
				SkipIndex = i + 1;
			}
			j--;
		}		
	}

	return pInitSubtitleFont( &Str[ SkipIndex ], a1, a2, a3, a4, a5, a6, a7, a8 );
}


typedef int( __cdecl* Type_RenderSubtitleLine )( HDC hdc, wchar_t* Str, int a3, int a4, int a5, int a6, int a7, int a8 );
Type_RenderSubtitleLine pRenderSubtitleLine;

int __cdecl hkRenderSubtitleLine( HDC hdc, wchar_t* Str, int a3, int a4, int a5, int a6, int a7, int a8 )// GDI
{
	int Len = wcslen( Str );

	int SkipIndex = 0;

	for( size_t i = 0, j = 7; i < Len && j > 0; i++ )
	{
		if( Str[ i ] == ',' )
		{
			if( j < 2 )
			{
				SkipIndex = i + 1;
			}
			j--;
		}
	}
	return pRenderSubtitleLine( hdc, &Str[ SkipIndex ], a3, a4, a5, a6, a7, a8 );
}

bool bDataCompare( const BYTE* pData, const BYTE* bMask, const char* szMask )
{
	for( ; *szMask; ++szMask, ++pData, ++bMask )
		if( *szMask == 'x' && *pData != *bMask )
			return false;
	return ( *szMask ) == NULL;
}

DWORD dwFindPattern( DWORD dwAddress, DWORD dwLen, BYTE *bMask, char * szMask )
{
	for( DWORD i = 0; i < dwLen; i++ )
		if( bDataCompare( ( BYTE* ) ( dwAddress + i ), bMask, szMask ) )
			return ( DWORD ) ( dwAddress + i );
	return NULL;
}

void *DetourFunc( BYTE *src, const BYTE *dst, const int len )
{
	BYTE *jmp = ( BYTE* ) VirtualAlloc( nullptr, len + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	DWORD dwback;

	VirtualProtect( src, len, PAGE_READWRITE, &dwback );

	__movsb( jmp, src, len );
	
	jmp += len;

	jmp[ 0 ] = 0xE9;
	*( DWORD* ) ( jmp + 1 ) = ( DWORD ) ( src + len - jmp ) - 5;

	src[ 0 ] = 0xE9;
	*( DWORD* ) ( src + 1 ) = ( DWORD ) ( dst - src ) - 5;

	VirtualProtect( src, len, dwback, &dwback );

	return ( jmp - len );
}

DWORD __stdcall dwThread( void* )
{
	HMODULE hmModule = GetModuleHandle( nullptr );

	IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast< IMAGE_DOS_HEADER* >( hmModule );

	if( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
	{
		MessageBoxA( 0, "Error 1", nullptr, 0 );
		return 0;
	}

	IMAGE_NT_HEADERS* pImageNtHeader = reinterpret_cast< IMAGE_NT_HEADERS* >( ( ( DWORD_PTR ) hmModule + pDosHeader->e_lfanew ) );

	if( pImageNtHeader->Signature != IMAGE_NT_SIGNATURE )
	{
		MessageBoxA( 0, "Error 2", nullptr, 0 );
		return 0;
	}

	DWORD dwSize = pImageNtHeader->OptionalHeader.SizeOfCode;
	DWORD dwStart = ( DWORD ) hmModule + pImageNtHeader->OptionalHeader.BaseOfCode;

	DWORD dwAddress = dwFindPattern( dwStart, dwSize, ( BYTE* ) "\x57\x56\x55\x53\x81\xEC\x00\x00\x00\x00\x8B\xB4\x24\x00\x00\x00\x00\xBB\x00\x00\x00\x00\x83\xFE\x00\x0F\x44\x9C\x24\x00\x00\x00\x00\x8D\x84\x24\x00\x00\x00\x00\x50", "xxxxxx????xxx????x????xxxxxxx????xxx????x" );

	if( !dwAddress )
	{
		MessageBoxA( 0, "Error 3", nullptr, 0 );
		return 0;
	}

	pInitSubtitleFont = ( Type_InitSubtitleFont ) DetourFunc( ( BYTE* ) dwAddress, ( BYTE* ) hkInitSubtitleFont, 0xA );

	if( !pInitSubtitleFont )
	{
		MessageBoxA( 0, "Error 4", nullptr, 0 );
		return 0;
	}
	//
	dwAddress = dwFindPattern( dwStart, dwSize, ( BYTE* ) "\x57\x56\x55\x53\x83\xEC\x4C\x8D\x04\x24\x50\xFF\x35\x00\x00\x00\x00", "xxxxxxxxxxxxx????" );

	if( !dwAddress )
	{
		MessageBoxA( 0, "Error 5", nullptr, 0 );
		return 0;
	}

	pRenderSubtitleLine = ( Type_RenderSubtitleLine ) DetourFunc( ( BYTE* ) dwAddress, ( BYTE* ) hkRenderSubtitleLine, 0x7 );

	if( !pRenderSubtitleLine )
	{
		MessageBoxA( 0, "Error 6", nullptr, 0 );
		return 0;
	}

	return 1;
}

extern "C" BOOL __declspec( dllexport ) __stdcall EnumProcesses( DWORD *lpidProcess, DWORD cb, LPDWORD lpcbNeeded )
{
	PROCESSENTRY32 pe32;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

	if( hProcessSnap == INVALID_HANDLE_VALUE )
		return FALSE;

	pe32.dwSize = sizeof( PROCESSENTRY32 );

	DWORD dwNeeded;

	if( lpcbNeeded == nullptr )
	{
		lpcbNeeded = &dwNeeded;
	}

	*lpcbNeeded = 0;


	if( Process32First( hProcessSnap, &pe32 ) )
	{
		do
		{
			if( lpidProcess )
				lpidProcess[ *lpcbNeeded ] = pe32.th32ProcessID;

			*lpcbNeeded++;
		}
		while( cb / sizeof( DWORD ) > *lpcbNeeded );
	}

	return *lpcbNeeded > 0;
}

extern "C" DWORD __declspec( dllexport ) __stdcall GetModuleBaseNameW( HANDLE hProcess, HMODULE hModule, LPWSTR lpBaseName, DWORD nSize )
{
	MODULEENTRY32 me32;

	HANDLE hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId( hProcess ) );

	if( hProcessSnap == INVALID_HANDLE_VALUE )
		return 0;

	me32.dwSize = sizeof( MODULEENTRY32 );

	if( Module32First( hProcessSnap, &me32 ) )
	{
		do
		{
			if( me32.hModule == hModule || me32.modBaseAddr == ( BYTE* ) hModule )
			{
				lstrcpyW( lpBaseName, me32.szModule );
			}
		}
		while( Module32Next( hProcessSnap, &me32 ) );
	}

	return 0;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread( nullptr, 0, reinterpret_cast< LPTHREAD_START_ROUTINE >( &dwThread ), hModule, 0, nullptr );
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

