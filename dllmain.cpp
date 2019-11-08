// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

typedef int (__cdecl* Type_InitSubtitleFont)( wchar_t *Str, int, int, int, int, int, int, int, int );
Type_InitSubtitleFont pInitSubtitleFont;

int __cdecl hkInitSubtitleFont( wchar_t *Str, int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8 )
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

	memcpy( jmp, src, len );	jmp += len;

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

