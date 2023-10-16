#include <stdio.h>
#include <windows.h>

#define error(str) printf("[-] %s: %d", str, GetLastError())

DWORD GetImageSize(LPBYTE dllbase)
{
    PIMAGE_DOS_HEADER DOS = (PIMAGE_DOS_HEADER)dllbase;
    PIMAGE_NT_HEADERS NT = (PIMAGE_NT_HEADERS)(dllbase + DOS->e_lfanew);
    return NT->OptionalHeader.SizeOfImage;
}

int main()
{
    const char* file_path = "C:\\windows\\system32\\taskmgr.exe";

    HANDLE hFile;
    DWORD dwFileSize, dwBytesRead, dwImageSize, dwAddressLocation;
    PDWORD pFunctionAddress, pNamesAddress;
    PWORD pOrdinalNamesAddress;
    PIMAGE_DOS_HEADER pDOS;
    PIMAGE_NT_HEADERS pNT;
    IMAGE_DATA_DIRECTORY ExportDirectory, ImportDirectory;
    PIMAGE_SECTION_HEADER pSECTION, pEXPORT = nullptr, pIMPORT = nullptr;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
    PIMAGE_THUNK_DATA pThunkData;
    PIMAGE_IMPORT_BY_NAME pImportByName;
    PIMAGE_EXPORT_DIRECTORY pExportTable;

    hFile = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, 3, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == NULL)
    {
        error("Error opening file");
        return 0;
    }
    printf("\\__[File Handle]\n\t\\_0x%p\n", hFile);

    if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE)
    {
        error("GetFileSize error");
        CloseHandle(hFile);
        return 0;
    }

    LPBYTE dllInfo = (LPBYTE)VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!ReadFile(hFile, dllInfo, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize)
    {
        error("ReadFile error");
        CloseHandle(hFile);
        VirtualFree(dllInfo, 0, MEM_RELEASE);
        return 0;
    }
    CloseHandle(hFile);

    dwImageSize = GetImageSize(dllInfo);
    LPBYTE lpBaseAddress = (LPBYTE)VirtualAlloc(NULL, dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    pDOS = (PIMAGE_DOS_HEADER)dllInfo;
    pNT = (PIMAGE_NT_HEADERS)(dllInfo + pDOS->e_lfanew);

    pNT->OptionalHeader.ImageBase = (DWORD)lpBaseAddress;
    memcpy((void*)(lpBaseAddress), (void*)dllInfo, pNT->OptionalHeader.SizeOfHeaders);

    ExportDirectory = pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    ImportDirectory = pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    pSECTION = IMAGE_FIRST_SECTION(pNT);
    for (int i = 0; i < pNT->FileHeader.NumberOfSections; i++)
    {
        if (ExportDirectory.VirtualAddress >= pSECTION->VirtualAddress && ExportDirectory.VirtualAddress < pSECTION->VirtualAddress + pSECTION->SizeOfRawData)
        {
            printf("\\__[%s]\n\t\\_[Virtual Address]\n\t\t\\0x%x\n\t\\_[Section Offset]\n\t\t\\_0x%x\n", (char*)(pSECTION->Name), pSECTION->VirtualAddress, pSECTION->PointerToRawData);
            pEXPORT = pSECTION;
        }
        if (ImportDirectory.VirtualAddress >= pSECTION->VirtualAddress && ImportDirectory.VirtualAddress < pSECTION->VirtualAddress + pSECTION->SizeOfRawData)
        {
            printf("\\__[%s]\n\t\\_[Virtual Address]\n\t\t\\0x%x\n\t\\_[Section Offset]\n\t\t\\_0x%x\n", (char*)(pSECTION->Name), pSECTION->VirtualAddress, pSECTION->PointerToRawData);
            pIMPORT = pSECTION;
        }

        memcpy((void*)(lpBaseAddress + pSECTION->VirtualAddress), (void*)(dllInfo + pSECTION->PointerToRawData), pSECTION->SizeOfRawData);
        pSECTION++;
    }

    if (pIMPORT == nullptr)
        printf("\n[*] Dll has no imports\n\n");
    else
    {
        printf("Imports:\n\n");
        pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(lpBaseAddress + ImportDirectory.VirtualAddress);
        while (pImportDescriptor->Name != NULL)
        {
            char* library_name = (char*)(lpBaseAddress + pImportDescriptor->Name);
            HMODULE hLibrary = LoadLibraryA(library_name);
            if (hLibrary == NULL)
            {
                error("Unable to load libary");
                VirtualFree(dllInfo, 0, MEM_RELEASE);
                VirtualFree(lpBaseAddress, 0, MEM_RELEASE);
                return 0;
            }
            printf("\\__[%s]\n", library_name);
            pThunkData = (PIMAGE_THUNK_DATA)(lpBaseAddress + pImportDescriptor->FirstThunk);
            while (pThunkData->u1.AddressOfData != NULL)
            {
                if (IMAGE_SNAP_BY_ORDINAL(pThunkData->u1.Ordinal))
                {
                    pThunkData->u1.Function = (DWORD)GetProcAddress(hLibrary, MAKEINTRESOURCEA(pThunkData->u1.Ordinal));
                    printf("Ordinal: %d\n", pThunkData->u1.Ordinal);
                }
                else
                {
                    pImportByName = (PIMAGE_IMPORT_BY_NAME)(lpBaseAddress + pThunkData->u1.AddressOfData);
                    printf("\t\\_[%s]\n", (char*)pImportByName->Name);
                    pThunkData->u1.Function = (DWORD)GetProcAddress(hLibrary, (char*)(pImportByName->Name));
                }
                pThunkData++;
            }
            pImportDescriptor++;
        }
    }

    if (pEXPORT == nullptr)
    {
        printf("No exports found");
    }
    else
    {
        printf("\nExports:\n\n");
        pExportTable = (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddress + ExportDirectory.VirtualAddress);

        pFunctionAddress = (PDWORD)(lpBaseAddress + pExportTable->AddressOfFunctions);
        pNamesAddress = (PDWORD)(lpBaseAddress + pExportTable->AddressOfNames);
        pOrdinalNamesAddress = (PWORD)(lpBaseAddress + pExportTable->AddressOfNameOrdinals);

        for (int i = 0; i < pExportTable->NumberOfNames; i++)
        {
            char* function_name = (char*)(lpBaseAddress + pNamesAddress[i]);
            dwAddressLocation = (DWORD)(lpBaseAddress + pFunctionAddress[pOrdinalNamesAddress[i]]);
            printf("\\__[%s]\n\t\\_0x%x\n", function_name, dwAddressLocation);
        }
    }

    VirtualFree(dllInfo, 0, MEM_RELEASE);
    VirtualFree(lpBaseAddress, 0, MEM_RELEASE);
    return 0;
}
