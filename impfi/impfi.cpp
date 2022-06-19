#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <sstream>

static int
ReadMagicNumber(
	FILE *f,
	const char *const Path,
	IMAGE_DOS_HEADER *DosHeader
)
{
	DosHeader->e_magic = 0;

	// Read magic number
	if ( 1 != fread( &DosHeader->e_magic, sizeof( DosHeader->e_magic ), 1, f ) )
	{
		printf( "%s - Too small to read magic number from DOS header\n", Path );
		return 1;
	}

	// Check 'MZ' signature
	if ( DosHeader->e_magic != 'ZM' )
	{
		printf( "%s - Incorrect magic number from DOS header\n", Path );
		return 2;
	}

	return 0;
}

static int
ReadNtHeaders(
	FILE *f,
	const char *const Path,
	IMAGE_DOS_HEADER *DosHeader,
	IMAGE_NT_HEADERS *NtHeaders
)
{
	// Initialize the rest of the header
	memset( &DosHeader->e_cblp, 0, sizeof( *DosHeader ) - sizeof( DosHeader->e_magic ) );

	// Read the rest of the header
	if ( 1 != fread( &DosHeader->e_cblp, sizeof( *DosHeader ) - sizeof( DosHeader->e_magic ), 1, f ) )
	{
		printf( "%s - DOS header incomplete after magic number\n", Path );
		return 1;
	}

	// Seek to the NT header offset from the beginning of the file
	if ( 0 != fseek( f, DosHeader->e_lfanew, SEEK_SET ) )
	{
		printf( "%s - NT header not found\n", Path );
		return 2;
	}

	// Read the NT header
	if ( 1 != fread( NtHeaders, sizeof( *NtHeaders ), 1, f ) )
	{
		printf( "%s - NT headers incomplete\n", Path );
		return 3;
	}

	// Check 'PE' signature
	if ( NtHeaders->Signature != 'EP' )
	{
		printf( "%s - Incorrect NT header signature\n", Path );
		return 4;
	}

	// Check architecture
#ifdef _M_X64
	if ( NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 )
#elif _M_IA64
	if ( NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_IA64 )
#else
	if ( NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 )
#endif
	{
		// Fail silently to ignore architectures that are not targeted
		return 5;
	}

	if ( NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC )
	{
		printf( "%s - Optional header magic number is inconsistent with NT header architecture, corrupted?\n", Path );
		return 6;
	}

	return 0;
}

static int
ReadSections(
	FILE *f,
	const char *const Path,
	IMAGE_FILE_HEADER *DosHeader,
	std::vector<IMAGE_SECTION_HEADER>& Sections
)
{
	Sections.clear();

	IMAGE_SECTION_HEADER SectionHeader;

	for ( WORD i = 0; i < DosHeader->NumberOfSections; i++ )
	{
		memset( &SectionHeader, 0, sizeof( SectionHeader ) );

		if ( 1 != fread( &SectionHeader, sizeof( SectionHeader ), 1, f ) )
		{
			printf( "%s - Corrupted section %i\n", Path, i );
			return 1;
		}

		Sections.push_back( SectionHeader );
	}

	return 0;
}

// Search all sections for the given relative virtual address
static DWORD
SectionRvaFileOffset( 
	IMAGE_FILE_HEADER *FileHeader,
	const std::vector<IMAGE_SECTION_HEADER>& Sections,
	DWORD Rva 
)
{
	for ( WORD i = 0; i < FileHeader->NumberOfSections; i++ )
	{
		DWORD VirtualAddress = Sections[i].VirtualAddress;
		DWORD VirtualSize = Sections[i].Misc.VirtualSize;

		if ( VirtualAddress <= Rva && Rva < VirtualAddress + VirtualSize )
		{
			return ( Rva - VirtualAddress ) + Sections[i].PointerToRawData;
		}
	}

	return 0;
}

// Enumerate import descriptors
// This could be refactored
static int
ReadImportDescriptors(
	FILE *f,
	const char *const Path,
	IMAGE_FILE_HEADER *FileHeader,
	IMAGE_OPTIONAL_HEADER *OptionalHeader,
	const std::vector<IMAGE_SECTION_HEADER>& Sections,
	std::vector<IMAGE_IMPORT_DESCRIPTOR>& ImportDescriptors,
	std::vector<std::string>& ImportDllNames,
	std::vector<std::vector<std::string>>& ImportThunkNames
)
{
	ImportDescriptors.clear();
	ImportDllNames.clear();
	ImportThunkNames.clear();

	DWORD NumberOfEntries = OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof( IMAGE_IMPORT_DESCRIPTOR ) - 1;
	DWORD Offset = SectionRvaFileOffset( FileHeader, Sections, OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );

	if ( 0 != fseek( f, (long)Offset, SEEK_SET ) )
	{
		printf( "%s - Import descriptor not found\n", Path );
		return 1;
	}

	IMAGE_IMPORT_DESCRIPTOR Descriptor;

	for ( DWORD i = 0; i < NumberOfEntries; i++ )
	{
		memset( &Descriptor, 0, sizeof( Descriptor ) );

		if ( 1 != fread( &Descriptor, sizeof( Descriptor ), 1, f ) )
		{
			printf( "%s - File too small to read import descriptor\n", Path );
			return 2;
		}

		ImportDescriptors.push_back( Descriptor );
	}
	
	char Name[32];
	IMAGE_THUNK_DATA Thunk;
	IMAGE_IMPORT_BY_NAME ImportName;
	DWORD ThunkOffset;

	for ( DWORD i = 0; i < NumberOfEntries; i++ )
	{
		Offset = SectionRvaFileOffset( FileHeader, Sections, ImportDescriptors[i].Name );

		if ( 0 != fseek( f, (long)Offset, SEEK_SET ) )
		{
			printf( "%s - Import descriptor name not found\n", Path );
			return 3;
		}

		Name[0] = 0;

		if ( 1 != fread( Name, sizeof(Name), 1, f ) )
		{
			printf( "%s - File too small to read import descriptor name\n", Path );
			return 4;
		}

		Name[sizeof(Name) - 1] = 0;

		ImportDllNames.push_back( Name );

		ThunkOffset = SectionRvaFileOffset( FileHeader, Sections, ImportDescriptors[i].FirstThunk );
		ImportThunkNames.push_back({});

		for ( ;; )
		{
			if ( 0 != fseek( f, (long)ThunkOffset, SEEK_SET ) )
			{
				printf( "%s - Import descriptor first thunk not found\n", Path );
				return 5;
			}

			if ( 1 != fread( &Thunk, sizeof( Thunk ), 1, f ) )
			{
				printf( "%s - File too small to read first thunk from file descriptor\n", Path );
				return 6;
			}

			Offset = SectionRvaFileOffset( FileHeader, Sections, (DWORD)Thunk.u1.AddressOfData );

			// Skip hint
			if ( 0 != fseek( f, (long)Offset, SEEK_SET ) )
			{
				printf( "%s - Thunk name not found\n", Path );
				return 7;
			}

			if ( 1 != fread( &ImportName, sizeof( ImportName.Hint ), 1, f))
			{
				printf( "%s - File too small to read thunk hint from thunk name\n", Path );
				return 8;
			}

			// Import by name hint is MZ at the last hunk
			// Thanks for this documentation microsoft.
			if ( ImportName.Hint == 'ZM' )
				break;

			Name[0] = 0;

			if ( 1 != fread( Name, sizeof( Name ), 1, f ) )
			{
				printf( "%s - File too small to read thunk name from thunk\n", Path );
				return 9;
			}

			Name[sizeof(Name) - 1] = 0;
			ImportThunkNames.back().push_back( Name );
			ThunkOffset += sizeof( IMAGE_THUNK_DATA );
		}
	}

	return 0;
}

int main( int argc, char **argv )
{
	if ( argc < 4 )
	{
		std::cout << "Import Finder - Finds all files which import any of the listed imports\n";
		std::cout << "\timpfi <directory> <extension> [imports]\n";
		std::cout << "\timpfi \"C:\\Windows\\System32\\drivers\" .sys IoCreateDevice ZwOpenProcess\n";
		std::cout << "Note - Make sure that if there are spaces in the directory, place the argument in quotation marks.\n";
		std::cout << "Note - You must also include the `.` in the extension.\n";
		return 0;
	}

	const char *const pszDirectory = argv[1];
	const char *const pszExtension = argv[2];
	int numImports = argc - 3;
	const char *const *const ppszImports = argv + 3;

	IMAGE_DOS_HEADER DosHeader;
	IMAGE_NT_HEADERS NtHeaders;
	std::vector<IMAGE_SECTION_HEADER> Sections;
	std::vector<IMAGE_IMPORT_DESCRIPTOR> ImportDescriptors;
	std::vector<std::string> ImportDllNames;
	std::vector<std::vector<std::string>> ImportThunkNames;
	std::string Path;

	std::ostringstream oss;
	std::ostringstream oss2;
	int importCount = 0;
	int numResults = 0;
	long SizeInBytes;

	for ( const auto& dirEntry : std::filesystem::directory_iterator( pszDirectory ) )
	{
		if ( dirEntry.path().extension() != pszExtension )
			continue;

		Path = dirEntry.path().generic_string();

		FILE *f = NULL;
		if ( 0 != fopen_s( &f, Path.c_str(), "rb" ) || !f )
			continue;

		// ReadMagicNumber initializes e_magic
		if ( 0 != ReadMagicNumber( f, Path.c_str(), &DosHeader ) )
		{
			fclose( f );
			continue;
		}
		
		// Checks NT headers signature, and checks architecture
		if ( 0 != ReadNtHeaders( f, Path.c_str(), &DosHeader, &NtHeaders ) )
		{
			fclose( f );
			continue;
		}

		// Read sections for virtual address translation in the file
		if ( 0 != ReadSections( f, Path.c_str(), &NtHeaders.FileHeader, Sections ) )
		{
			fclose( f );
			continue;
		}

		// Read import descriptors and dll import names
		if ( 0 != ReadImportDescriptors( f, Path.c_str(), &NtHeaders.FileHeader, &NtHeaders.OptionalHeader, Sections, ImportDescriptors, ImportDllNames, ImportThunkNames ) )
		{
			fclose( f );
			continue;
		}

		// Bad C++
		// Use two string streams to put the path BEFORE listing imports because we have to make sure it has the listed imports
		oss.str("");
		oss2.str("");
		importCount = 0;

		// Probably a more efficient way to do this
		for ( size_t i = 0; i < ImportThunkNames.size(); i++ )
		{
			for ( size_t j = 0; j < ImportThunkNames[i].size(); j++ )
			{
				// Loop thru imports
				for ( int k = 0; k < numImports; k++ )
				{
					if ( 0 == ImportThunkNames[i][j].compare( ppszImports[k] ) )
					{
						if ( numImports > 1 )
							oss << '\t' << ppszImports[k] << '\n';
						importCount++;
					}
				}
			}
		}

		// If there are any imports, name the path, then list the imports
		if ( importCount )
		{
			rewind( f );
			fseek( f, 0, SEEK_END );
			SizeInBytes = ftell( f );

			oss2 << numResults++ << " - " << Path << " (" << SizeInBytes / 1024.f << " kb)" << ", " << importCount << " import(s) found\n";
			oss2 << oss.str();
			std::cout << oss2.str();
		}

		fclose( f );
	}
}
