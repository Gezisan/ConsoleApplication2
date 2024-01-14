#include<Windows.h>
#include<iostream>
#include <TlHelp32.h>
#include <psapi.h>
using namespace std;

class PEFile {
private:
    HANDLE hFile;                                   //文件句柄
    HANDLE hProcess;                                //进程句柄
    DWORD ProcessBaseAddr;                          //进程基址
    BYTE* FileBuffer;                               //文件缓冲指针
    BYTE* imageBuffer;                              //映像缓冲指针
    DWORD fileBufferSize;                           //文件缓冲大小
    DWORD imageBufferSize;                          //映像缓冲大小

    //FileBuffer的各个指针
    PIMAGE_DOS_HEADER pDosHeader;                   //Dos头
    PIMAGE_NT_HEADERS pNtHeader;                    //NT头
    PIMAGE_FILE_HEADER pFileHeader;                 //标准PE头
    PIMAGE_OPTIONAL_HEADER pOptionalHeader;         //扩展PE头
    PIMAGE_DATA_DIRECTORY pDataDirectory;           //数据目录表
    PIMAGE_EXPORT_DIRECTORY pExportDirectory;       //导出表
    PIMAGE_BASE_RELOCATION pBaseRelocation;         //重定位表
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;     //导入表
    PIMAGE_SECTION_HEADER pSectionHeader;           //节表

    //dos头关键成员
    WORD dosSignature;          //dos签名
    LONG   NToffset;            //nt头偏移

    //NT头关键成员
    DWORD peSignature;

    //标准PE头关键成员
    WORD Machine;               //cpu型号
    DWORD numberOfSections;     //节区数
    WORD sizeOfOptionalHeader;  //可选pe头大小

    //可选PE头关键成员
    DWORD addressOfEntryPoint;  //程序入口点EP
    DWORD imageBase;            //内存镜像基址
    DWORD sectionAlignment;     //内存对齐大小
    DWORD fileAlignment;        //文件对齐大小
    DWORD sizeOfImage;          //内存映像大小
    DWORD sizeOfHeaders;        //各种头的大小

    //初始化各个表头指针
    void InitHeaders() {
        pDosHeader = (IMAGE_DOS_HEADER*)FileBuffer;//DOS头
        pNtHeader = (IMAGE_NT_HEADERS*)(FileBuffer + pDosHeader->e_lfanew);//NT头
        pFileHeader = (IMAGE_FILE_HEADER*)((DWORD)pNtHeader + sizeof(DWORD));//标准PE头
        pOptionalHeader = (IMAGE_OPTIONAL_HEADER*)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));//可选PE头
        pSectionHeader = (IMAGE_SECTION_HEADER*)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);//节表
        pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionalHeader->DataDirectory);//数据目录表
        pBaseRelocation = (PIMAGE_BASE_RELOCATION)(FileBuffer + RVA2FOA(pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));//重定位表
        pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(FileBuffer + RVA2FOA(pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));//导入表
        if (pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)//如果存在导出表则获取导出表地址,否则置空
            pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(FileBuffer + RVA2FOA(pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));//导出表
        else pExportDirectory = NULL;

    }

    //初始化FileBuffer关键成员
    void InitKeyMembers() {

        //dos头
        dosSignature = pDosHeader->e_magic;
        NToffset = pDosHeader->e_lfanew;

        //NT头
        peSignature = pNtHeader->Signature;

        //标准PE头 20字节
        Machine = pFileHeader->Machine;
        numberOfSections = pFileHeader->NumberOfSections;
        sizeOfOptionalHeader = pFileHeader->SizeOfOptionalHeader;

        //可选头,根据32/64位有不同大小
        addressOfEntryPoint = pOptionalHeader->AddressOfEntryPoint;
        imageBase = pOptionalHeader->ImageBase;
        sectionAlignment = pOptionalHeader->SectionAlignment;
        fileAlignment = pOptionalHeader->FileAlignment;
        sizeOfImage = pOptionalHeader->SizeOfImage;
        sizeOfHeaders = pOptionalHeader->SizeOfHeaders;
    }

    //打印DOS头
    void showDosHeader() {
        printf("\n----------DosHeader----------\n");
        printf("DosSignature: %x\n", dosSignature);
        printf("NtHeaderOffset: %x\n", NToffset);
        printf("\n----------DosHeader----------\n");
    }

    //打印标准Pe头
    void showFileHeader() {
        printf("\n----------FileHeader----------\n");
        printf("Machine: %x\n", Machine);
        printf("NumberOfSections: %x\n", numberOfSections);
        printf("SizeOfOptionalHeader: %x\n", sizeOfOptionalHeader);
        printf("\n----------FileHeader----------\n");
    }

    //打印可选PE头
    void showOptionalHeader() {
        printf("\n----------OptionalHeader----------\n");
        printf("EntryPoint: %x\n", addressOfEntryPoint);
        printf("ImageBase: %x\n", imageBase);
        printf("SectionAlignment: %x\n", sectionAlignment);
        printf("FileAlignment: %x\n", fileAlignment);
        printf("SizeOfImage; %x\n", sizeOfImage);
        printf("SizeOfHeaders: %x\n", sizeOfHeaders);
        printf("\n----------OptionalHeader----------\n");
    }

    //打印NT头
    void showNtHeader() {
        printf("\n-----------NtHeader----------\n");
        printf("PeSignature: %x\n", peSignature);
        showFileHeader();
        showOptionalHeader();
        printf("\n-----------NtHeader----------\n");
    }

    //打印节表
    void showSectionHeaders() {
        printf("\n----------SectionHeaders----------\n");
        for (DWORD i = 0; i < numberOfSections; i++) {
            //逐个读取节表并打印
            printf("\n----------Section%d----------\n", i);
            printf("Name: %8s\n", pSectionHeader[i].Name);
            printf("VirtualSize: %x\n", pSectionHeader[i].Misc.VirtualSize);
            printf("VirtualAddress: %x\n", pSectionHeader[i].VirtualAddress);
            printf("SizeOfRawData: %x\n", pSectionHeader[i].SizeOfRawData);
            printf("PointerToRawData: %x\n", pSectionHeader[i].PointerToRawData);
            printf("Characteristics: %x\n", pSectionHeader[i].Characteristics);
            printf("\n----------Section%d----------\n", i);
        }
        printf("\n----------SectionHeaders----------\n");
    }

    //设置FileBuffer
    void SetFileBuffer(BYTE* NewFileBuffer) {
        if (FileBuffer)
            delete[] FileBuffer;       //删除原始空间
        FileBuffer = NewFileBuffer;//指向新的空间
        Init();                    //初始化
    }

    //设置ImageBuffer
    void SetImageBuffer(BYTE* NewImageBuffer) {
        if (imageBuffer)
            delete[] imageBuffer;
        imageBuffer = NewImageBuffer;
    }

    //将FileBuffer拉伸成为ImageBuffer
    void FileBufferToImageBuffer() {
        //1. 申请空间用于存储Image
        imageBuffer = new BYTE[sizeOfImage];
        imageBufferSize = sizeOfImage;
        if (!imageBuffer)
        {
            printf("申请空间失败!\n");
            system("pause");
            return;
        }
        memset(imageBuffer, 0, sizeOfImage);            //初始化内存空间,全部清零
        memcpy(imageBuffer, FileBuffer, sizeOfHeaders); //直接复制各个表头

        //2. 拉伸FileBuffer并写入ImageBuffer
        for (DWORD i = 0; i < numberOfSections; i++) {
            memcpy(imageBuffer + pSectionHeader[i].VirtualAddress, FileBuffer + pSectionHeader[i].PointerToRawData, pSectionHeader[i].SizeOfRawData);
            //起始地址是imageBase+节区起始地址RVA SizeOfData是节区在文件中保存的数据 
            //不使用VirtualSize的原因是例如.textbss段 SizeOfData=0 VirtualSize=10000 
            //显然在文件中没有数据需要写入内存,只是在内存中占用那么多大小的空间而已
        }
    }

    //将ImageBuffer压缩为FileBuffer
    void ImageBufferToFileBuffer() {
        //1. 申请空间用于存储ImageBuffer压缩后的FileBuffer
        DWORD NewFileBufferSize = pSectionHeader[numberOfSections - 1].PointerToRawData + pSectionHeader[numberOfSections - 1].SizeOfRawData;
        BYTE* NewFileBuffer = new BYTE[NewFileBufferSize];//最后一个节区的文件起始地址+文件大小即为PE文件大小
        memset(NewFileBuffer, 0, NewFileBufferSize);

        //2. 将ImageBuffer的内容压缩并写入FileBuffer
        for (DWORD i = 0; i < numberOfSections; i++) //复制节区  
        {
            memcpy(NewFileBuffer + pSectionHeader[i].PointerToRawData, imageBuffer + pSectionHeader[i].VirtualAddress, pSectionHeader[i].SizeOfRawData);
            //节区文件偏移起始地址 节区内存偏移起始地址 节区文件大小 
            //注意这里第三个参数不要使用VirtualSize 否则可能会导致缓冲区溢出
            //(例如: .textbss段在文件中占用空间为0 但是内存中的大小为0x10000 所以这段没有必要写入文件中)
        }
        memcpy(NewFileBuffer, imageBuffer, sizeOfHeaders); //复制各个表头
        SetFileBuffer(NewFileBuffer);                      //重新设置FileBuffer
    }

    //获取进程基址
    DWORD GetProcessBaseAddress(HANDLE hProcess) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        DWORD baseAddress = 0;

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                TCHAR szModName[MAX_PATH];
                if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                    sizeof(szModName) / sizeof(TCHAR))) {
                    MODULEINFO moduleInfo;
                    if (GetModuleInformation(hProcess, hMods[i], &moduleInfo, sizeof(moduleInfo))) {
                        baseAddress = (uintptr_t)moduleInfo.lpBaseOfDll;
                        break; // We found the first module's base address
                    }
                }
            }
        }
        return baseAddress;
    }

public:
    //创建进程并获取进程基址
    BOOL CreateProcessWrapper(LPCTSTR applicationName, LPTSTR commandLine) {
        STARTUPINFO startupInfo;
        PROCESS_INFORMATION processInfo;
        ZeroMemory(&startupInfo, sizeof(startupInfo));
        startupInfo.cb = sizeof(startupInfo);

        BOOL success = CreateProcess(
            applicationName,
            commandLine,
            NULL, NULL, FALSE, 0, NULL, NULL,
            &startupInfo,
            &processInfo
        );
        if (success) {
            hProcess = processInfo.hProcess;
            ProcessBaseAddr = GetProcessBaseAddress(hProcess);
        }
        return success;
    }

    //将FileBuffer写入文件
    BOOL FileBufferWriteToFile(const WCHAR* FileName) {
        //创建文件 注意这里第三个参数不能用GENERIC_ALL 推测是由于可执行权限导致出错 仅读写没有问题 
        //CREATE_ALWAYS 无论文件是否存在都会写入
        HANDLE hFile = CreateFile(FileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return FALSE;
        return WriteFile(hFile, FileBuffer, fileBufferSize, NULL, NULL); // 写入文件
    }

    //将ImageBuffer写入文件
    BOOL ImageBufferWriteToFile(const WCHAR* FileName) {
        HANDLE hFile = CreateFile(FileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return FALSE;
        return WriteFile(hFile, imageBuffer, sizeOfImage, NULL, NULL);
    }

    //扩大filebuffer大小 ExSize为文件对齐后的额外空间大小
    void ExpandFileBuffer(DWORD ExSize) {
        BYTE* NewBuffer = new BYTE[fileBufferSize + ExSize];
        memset(NewBuffer + fileBufferSize, 0, ExSize);//额外空间清零
        memcpy(NewBuffer, FileBuffer, fileBufferSize);//复制原始数据
        fileBufferSize += ExSize;//调整大小
        SetFileBuffer(NewBuffer);
    }

    //扩大imgaebuffer大小
    void ExpandImageBuffer(DWORD ExSize) {
        BYTE* NewBuffer = new BYTE[imageBufferSize + ExSize];
        memset(NewBuffer + imageBufferSize, 0, ExSize);
        memcpy(NewBuffer, imageBuffer, imageBufferSize);
        imageBufferSize += ExSize;
        SetImageBuffer(NewBuffer);
    }

    PEFile(LPCWCHAR FileName) {
        hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);  //打开文件
        if (!hFile) {
            printf("OpenFileFailure!\n");
            exit(0);
        }

        fileBufferSize = GetFileSize(hFile, NULL);   //获取文件大小
        FileBuffer = new BYTE[fileBufferSize];     //分配内存空间用于存储文件

        if (!FileBuffer) {
            printf("AllocFileBufferMemoryFailure!\n");
            exit(0);
        }

        if (!ReadFile(hFile, FileBuffer, fileBufferSize, NULL, NULL)) //读取文件并存储到内存中
        {
            delete[] FileBuffer;
            printf("ReadFileFailure!\n");
            exit(0);
        }

        CloseHandle(hFile);//读取完后关闭文件

        InitHeaders();
        InitKeyMembers();
        FileBufferToImageBuffer();//创建ImageBuffer

        hProcess = NULL;
        ProcessBaseAddr = 0;
    }

    //初始化表头指针和关键变量
    void Init() {
        InitHeaders();
        InitKeyMembers();
        //InitImageHeaders();
    }

    //打印Pe文件信息
    void showPeFile() {
        showDosHeader();
        showNtHeader();
        showSectionHeaders();
        PrintDirectory();
        PrintExportDirectory();
        PrintRelocationTable();
        PrintImportTable();
    }

    //打印数据目录表
    void PrintDirectory() {
        PIMAGE_DATA_DIRECTORY pDirectory = pOptionalHeader->DataDirectory;
        printf("\n**********数据目录表**********\n");
        for (DWORD i = 0; i < pOptionalHeader->NumberOfRvaAndSizes; i++) {
            switch (i) {
            case IMAGE_DIRECTORY_ENTRY_EXPORT:
                printf("\n==========导出表==========\n");
                break;
            case IMAGE_DIRECTORY_ENTRY_IMPORT:
                printf("\n==========导入表==========\n");
                break;
            case IMAGE_DIRECTORY_ENTRY_RESOURCE:
                printf("\n==========资源目录==========\n");
                break;
            case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
                printf("\n==========异常目录==========\n");
                break;
            case IMAGE_DIRECTORY_ENTRY_SECURITY:
                printf("\n==========安全目录=========\n");
                break;
            case IMAGE_DIRECTORY_ENTRY_BASERELOC:
                printf("\n==========重定位基本表==========\n");
                break;
            case IMAGE_DIRECTORY_ENTRY_DEBUG:
                printf("\n==========调试目录==========\n");
                break;
            case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
                printf("\n==========描述字串==========\n");
                break;
            case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
                printf("\n==========机器值==========\n");
                break;
            case IMAGE_DIRECTORY_ENTRY_TLS:
                printf("\n==========TLS目录==========\n");
                break;
            case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
                printf("\n==========载入配置目录==========\n");
                break;
            case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
                printf("\n==========绑定输入表==========\n");
                break;
            case IMAGE_DIRECTORY_ENTRY_IAT:
                printf("\n==========导入地址表==========\n");
                break;
            case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
                printf("\n==========延迟导入表==========\n");
                break;
            case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
                printf("\n==========COM信息==========\n");
                break;
            case 15:
                printf("\n==========保留表==========\n");
                break;
            }
            printf("VirtualAddress=%x\nSize=%x\nFOA=%x\n", pDirectory[i].VirtualAddress, pDirectory[i].Size, RVA2FOA(pDirectory[i].VirtualAddress));

        }
        printf("\n**********数据目录表打印完毕**********\n\n");

    }

    //通过函数名获取导出函数地址
    DWORD GetFuncAddrByName(const char* FuncName) {
        WORD* pExportFuncOridinalsTable = (WORD*)(RVA2FOA(pExportDirectory->AddressOfNameOrdinals) + FileBuffer);//导出函数序号表
        DWORD* pExportFuncAddressTable = (DWORD*)(RVA2FOA(pExportDirectory->AddressOfFunctions) + FileBuffer);//导出函数地址表
        DWORD* pExportFuncNamesTable = (DWORD*)(RVA2FOA(pExportDirectory->AddressOfNames) + FileBuffer);//导出函数名称表

        DWORD pos = -1, OridinalNum = 0;
        //1. 通过导出函数名称表得到序号表下标
        for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
            //注意导出函数名称表表项是字符串指针 该指针值为RVA
            if (strcmp(FuncName, (char*)(RVA2FOA(pExportFuncNamesTable[i]) + FileBuffer)) == 0)
            {
                pos = i;
                break;
            }
        }
        if (pos == -1)//查找失败
            return 0;

        //2. 通过序号表得到序号
        OridinalNum = pExportFuncOridinalsTable[pos];

        //3. 得到函数地址
        return pExportFuncAddressTable[OridinalNum];
    }

    //通过函数序号获取导出函数地址
    DWORD GetFuncAddrByOridinals(WORD OridinalNum) {
        DWORD* pExportFuncAddressTable = (DWORD*)(RVA2FOA(pExportDirectory->AddressOfFunctions) + FileBuffer);//导出函数地址表
        return pExportFuncAddressTable[OridinalNum - pExportDirectory->Base];//减去Base值作为索引直接查找函数地址
    }

    //根据导出函数序号返回导出函数名
    PCHAR GetFuncNameByOridinals(WORD OridinalNum) {
        WORD* pExportFuncOridinalsTable = (WORD*)(RVA2FOA(pExportDirectory->AddressOfNameOrdinals) + FileBuffer);//导出函数序号表
        DWORD* pExportFuncNamesTable = (DWORD*)(RVA2FOA(pExportDirectory->AddressOfNames) + FileBuffer);//导出函数名称表
        for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
        {
            if (pExportFuncOridinalsTable[i] == OridinalNum)//实际存储的序号=函数序号-base
                return (PCHAR)(RVA2FOA(pExportFuncNamesTable[i]) + FileBuffer);
        }
        return NULL;//没有找到说明是无名函数
    }

    //打印导出表详细信息
    void PrintExportDirectory() {
        //不存在导出表
        if (!pExportDirectory)
        {
            printf("**********不存在导出表**********\n");
            return;
        }
        printf("\n==========导出表==========\n");
        printf("Name: %x (%s)\n", pExportDirectory->Name, (char*)(FileBuffer + RVA2FOA(pExportDirectory->Name)));
        printf("Base: %x\n", pExportDirectory->Base);
        printf("NumberOfFunctions: \t%x\n", pExportDirectory->NumberOfFunctions);
        printf("NumberOfNames: \t\t%x\n", pExportDirectory->NumberOfNames);
        printf("AddressOfFunctions: \tRVA=%x\tFOA=%x\n", pExportDirectory->AddressOfFunctions, RVA2FOA(pExportDirectory->AddressOfFunctions));
        printf("AddressOfNames: \tRVA=%x\tFOA=%x\n", pExportDirectory->AddressOfNames, RVA2FOA(pExportDirectory->AddressOfNames));
        printf("AddressOfNameOrdinals: \tRVA=%x\tFOA=%x\n", pExportDirectory->AddressOfNameOrdinals, RVA2FOA(pExportDirectory->AddressOfNameOrdinals));

        WORD* pExportFuncOridinalsTable = (WORD*)(RVA2FOA(pExportDirectory->AddressOfNameOrdinals) + FileBuffer);//导出函数序号表
        DWORD* pExportFuncAddressTable = (DWORD*)(RVA2FOA(pExportDirectory->AddressOfFunctions) + FileBuffer);//导出函数地址表
        DWORD* pExportFuncNamesTable = (DWORD*)(RVA2FOA(pExportDirectory->AddressOfNames) + FileBuffer);//导出函数名称表

        printf("\nOridinal\t     RVA\t     FOA\tFunctionName\n");

        for (DWORD i = 0; i < pExportDirectory->NumberOfFunctions; i++) {
            if (pExportFuncAddressTable[i] == 0)//地址为零则跳过
                continue;
            PCHAR FuncName = NULL;
            //由于导出函数序号表仅保存有名函数序号,所以有序号必定有名称,否则无名称
            //函数序号=函数地址表下标+Base
            printf("%08x\t%08x\t%08x\t", i + pExportDirectory->Base, pExportFuncAddressTable[i], RVA2FOA(pExportFuncAddressTable[i]));
            //是否存在函数名要单独判断 存储序号=函数序号-Base,故传递i即可
            if (FuncName = GetFuncNameByOridinals(i))
                printf("%s\n", FuncName);
            else
                printf("NONAME\n");
        }
        printf("\n==========导出表结束==========\n");
    }

    //打印重定位表的某个块
    void PrintRelocationBlock(PIMAGE_BASE_RELOCATION pRelocationBlock) {
        PWORD pBlock = (PWORD)((DWORD)pRelocationBlock + 8);//注意每个表项占2字节 但是高4位用来判断是否需要修改
        DWORD PageOffset = pRelocationBlock->VirtualAddress;//每个块的虚拟地址即为页面起始地址

        printf("序号\t属性\t     RVA\t     FOA\t指向RVA\n");
        for (DWORD i = 0; i < (pRelocationBlock->SizeOfBlock - 8) / 2; i++) {
            //每块高四位用作属性判断,低12位才是页内偏移值 还要注意与运算优先级低于+ 不用括号会导致出错 
            //指向的RVA即需要矫正的地址
            printf("%04x\t%4x\t%08x\t%08x\t%08x\n", i, pBlock[i] >> 12, (pBlock[i] & 0x0fff) + PageOffset, RVA2FOA((pBlock[i] & 0x0fff) + PageOffset), *(DWORD*)(FileBuffer + RVA2FOA((pBlock[i] & 0x0fff) + PageOffset)) & 0x00ffffff);
        }
    }

    //打印重定位表
    void PrintRelocationTable() {
        PIMAGE_BASE_RELOCATION pRelocationTable = pBaseRelocation;
        printf("\n==========重定位表==========\n");
        printf("序号\t    区段\t     RVA\t     FOA\t项目数\n");

        //表块全为0时结束
        DWORD count = 0;
        while (pRelocationTable->VirtualAddress || pRelocationTable->SizeOfBlock) {
            //项目数=(sizeofBlock-8)/2
            printf("%4d\t%8s\t%08x\t%08x\t%08x\n", count++, GetSectionNameByRva(pRelocationTable->VirtualAddress), pRelocationTable->VirtualAddress, RVA2FOA(pRelocationTable->VirtualAddress), (pRelocationTable->SizeOfBlock - 8) / 2);
            pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);//注意这里应该将指针值强转后+块大小指向下一个块
        }

        pRelocationTable = pBaseRelocation;
        count = 0;
        while (pRelocationTable->VirtualAddress || pRelocationTable->SizeOfBlock) {
            printf("\n==========Block%d==========\n", count++);
            PrintRelocationBlock(pRelocationTable);//打印第i个块
            pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);
        }

        printf("\n==========重定位表结束==========\n");
    }

    //打印INT表
    void PrintINT(PIMAGE_IMPORT_DESCRIPTOR pImportTable) {
        printf("\n==========INT==========\n");
        printf("ThunkRVA\tThunkFOA\tThunkVal\tFuncName\n\n");
        PIMAGE_THUNK_DATA32 pThunkData = (PIMAGE_THUNK_DATA32)(RVA2FOA(pImportTable->OriginalFirstThunk) + FileBuffer);
        while (pThunkData->u1.Ordinal) {
            //最高位为1时表示按序号导入,低31位作为序号值
            printf("%08x\t%08x\t%08x\t", FOA2RVA((DWORD)pThunkData - (DWORD)FileBuffer), (DWORD)pThunkData - (DWORD)FileBuffer, pThunkData->u1.Ordinal);
            if (pThunkData->u1.Ordinal & 0x80000000) {
                printf("%08x\n", pThunkData->u1.Ordinal & 0x7FFFFFFF);
            }
            //最高位为0时表示按函数名称导入,值作为指向IMAGE_IMPORT_BY_NAME结构体地址的RVA
            else
            {
                PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(RVA2FOA(pThunkData->u1.AddressOfData) + FileBuffer);
                printf("%s\n", pImportName->Name);
            }
            pThunkData++;
        }
    }
    //打印IAT表
    void PrintIAT(PIMAGE_IMPORT_DESCRIPTOR pImportTable) {
        printf("\n==========IAT==========\n");
        PDWORD pThunkData = (PDWORD)(RVA2FOA(pImportTable->FirstThunk) + FileBuffer);
        printf(" FuncRVA\t FuncFOA\tFuncAddr\n");
        while (*pThunkData) {
            printf("%08x\t%08x\t%08x\n", *pThunkData, RVA2FOA(*pThunkData), *pThunkData + imageBase);
            pThunkData++;
        }
    }
    //打印导入表
    void PrintImportTable() {
        PIMAGE_IMPORT_DESCRIPTOR pImportTable = pImportDescriptor;
        printf("\n**********导入表**********\n");
        printf("DllName\t\t\t INT RVA\tTimeStamp\tIAT RVA\n");
        while (pImportTable->OriginalFirstThunk) {
            printf("%-24s%08x\t%08x\t%08x\n", (RVA2FOA(pImportTable->Name) + FileBuffer), pImportTable->OriginalFirstThunk, pImportTable->TimeDateStamp, pImportTable->FirstThunk);
            pImportTable++;
        }

        pImportTable = pImportDescriptor;
        while (pImportTable->OriginalFirstThunk) {

            printf("\n==========DllName:%s==========\n", RVA2FOA(pImportTable->Name) + FileBuffer);
            PrintINT(pImportTable);
            PrintIAT(pImportTable);

            pImportTable++;
        }
        printf("\n**********导入表**********\n");
    }

    //通过RVA判断所属区段名
    PCHAR GetSectionNameByRva(DWORD RVA) {
        for (DWORD i = 0; i < numberOfSections; i++) {
            if (RVA >= pSectionHeader[i].VirtualAddress && RVA < pSectionHeader[i].VirtualAddress + AlignSize(pSectionHeader[i].Misc.VirtualSize, 0x1000))//成功找到所属节区
                return (PCHAR)pSectionHeader[i].Name;
        }
    }

    //RVA转FOA
    DWORD RVA2FOA(DWORD RVA) {
        DWORD FOA = 0;
        //1. 判断RVA属于哪个节区 节区内存起始地址<=RVA<=节区内存起始地址+节区大小 内存大小需要对齐 注意右边界应该是开区间
        //2. FOA=RVA-VirtualAddress+PointerToRawData
        for (DWORD i = 0; i < numberOfSections; i++) {
            if (RVA >= pSectionHeader[i].VirtualAddress && RVA < pSectionHeader[i].VirtualAddress + AlignSize(pSectionHeader[i].Misc.VirtualSize, 0x1000))//成功找到所属节区
            {
                FOA = RVA - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData;
                break;
            }
        }
        return FOA;
    }

    //FOA转RVA
    DWORD FOA2RVA(DWORD FOA) {
        DWORD RVA = 0;
        //1. 判断FOA属于哪个节区 节区文件起始地址<=FOA<=节区文件起始地址+节区大小 文件大小默认是对齐值
        //2. RVA=FOA-PointerToRawData+VirtualAddress
        for (DWORD i = 0; i < numberOfSections; i++) {
            if (FOA >= pSectionHeader[i].PointerToRawData && FOA < pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData) {
                RVA = FOA - pSectionHeader[i].PointerToRawData + pSectionHeader[i].VirtualAddress;
                break;
            }
        }
        return RVA;

    }

    //输入原始大小和对齐值返回对齐后的大小
    DWORD AlignSize(DWORD OrigSize, DWORD AlignVal) {
        //通过对对齐值取模判断是否对齐,如果对齐则返回原值,否则返回对齐后的值
        return OrigSize % AlignVal ? (OrigSize / AlignVal + 1) * AlignVal : OrigSize;
    }

    //计算call/jmp指令的偏移值 目的地址-(当前指令地址+5)
    DWORD OffsetOfCallAndJmp(DWORD DesAddr, DWORD SelfAddr) {
        return DesAddr - (SelfAddr + 5);
    }

    //创建新的节区 返回新节区指针
    PIMAGE_SECTION_HEADER CreateNewSection(const char* NewSectionName, DWORD NewSectionSize) {
        //1. 检查节表空闲区是否足够保存新的节表 80字节
        //空白空间起始地址=NT头偏移+NT头大小+所有节表大小
        DWORD BlankMemAddr = (NToffset + sizeof(IMAGE_NT_HEADERS)) + numberOfSections * sizeof(IMAGE_SECTION_HEADER);
        DWORD BlankMemSize = sizeOfHeaders - BlankMemAddr;//空白空间大小=SizeOfHeaders-各个表头大小-所有节表大小
        if (BlankMemSize < sizeof(IMAGE_SECTION_HEADER) * 2)
            return NULL;

        //2. 申请新的空间
        ExpandFileBuffer(NewSectionSize);
        PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)(FileBuffer + BlankMemAddr);//指向新增的节表

        //3. 复制.text段的节表信息
        for (DWORD i = 0; i < numberOfSections; i++) {
            if (!strcmp((char*)pSectionHeader[i].Name, ".text"))
            {
                memcpy(pNewSectionHeader, (LPVOID)&pSectionHeader[i], sizeof(IMAGE_SECTION_HEADER));
                break;
            }
        }

        //4. 修正PE文件信息
        //标准PE头
        pFileHeader->NumberOfSections = ++numberOfSections;         //NumberOfSections +1

        //节区头 
        memcpy(pNewSectionHeader->Name, NewSectionName, strlen(NewSectionName));//name
        pNewSectionHeader->Misc.VirtualSize = NewSectionSize;               //virtualsize

        //注意这里必须先修改VirtualAddress
        //virtualaddress 各段间是紧邻着的 所以可以根据上个段的末尾来确定新段的起始地址 上个段的起始地址+上个段的大小对于0x1000向上取整即可
        pNewSectionHeader->VirtualAddress = AlignSize(pSectionHeader[numberOfSections - 2].VirtualAddress + pSectionHeader[numberOfSections - 2].SizeOfRawData, 0x1000);
        pNewSectionHeader->SizeOfRawData = NewSectionSize;//SizeOfRawData
        //PointerToRawData 文件偏移=上个段的文件起始地址+段在文件中的大小
        pNewSectionHeader->PointerToRawData = pSectionHeader[numberOfSections - 2].PointerToRawData + pSectionHeader[numberOfSections - 2].SizeOfRawData;
        pNewSectionHeader->Characteristics |= 0x20000000;           //Characteristics 可执行权限

        //可选头
        pOptionalHeader->SizeOfImage = sizeOfImage = sizeOfImage + AlignSize(NewSectionSize, 0x1000);//可选PE头 SizeOfImage 必须是内存对齐的整数倍 直接添加一页大小

        return pNewSectionHeader;
    }

    //通过创建新节区的方式注入代码
    BOOL InjectCodeByCreateNewSection() {
        //1. 创建新的节区
        PIMAGE_SECTION_HEADER pNewSectionHeader = CreateNewSection(".inject", 0x1000);

        //修正可选头
        DWORD OEP = addressOfEntryPoint; //保存OEP
        pOptionalHeader->DllCharacteristics &= 0xFFFFFFBF;//取消ASLR随机基址 随机基址的值是0x40 所以和(0xFFFFFFFF-0x40)进行与运算即可
        pOptionalHeader->AddressOfEntryPoint = addressOfEntryPoint = pNewSectionHeader->VirtualAddress;//修改EP 注意ep=rva 不用加基址

        //2. 将代码写入新的节区
        BYTE InjectCode[18] = {         //偏移  指令
            0x6a,0x00,                  //0     push 0
            0x6a,0x00,                  //0     push 0
            0x6a,0x00,                  //0     push 0
            0x6a,0x00,                  //0     push 0
            0xe8,0x00,0x00,0x00,0x00,   //8     call MessageBox MessageBox=0x763C0E50 这个地址会随着系统启动而变化
            0xe9,0x00,0x00,0x00,0x00    //13    jmp oep

        };
        DWORD MessageBoxAddr = 0x76260E50;
        //矫正call和jmp地址 
        *(DWORD*)&InjectCode[9] = OffsetOfCallAndJmp(MessageBoxAddr, imageBase + pNewSectionHeader->VirtualAddress + 8);
        *(DWORD*)&InjectCode[14] = OffsetOfCallAndJmp(OEP, pNewSectionHeader->VirtualAddress + 13);//跳转回oep正常执行程序     
        memcpy(FileBuffer + pNewSectionHeader->PointerToRawData, InjectCode, sizeof(InjectCode));//将代码写入新的内存空间            

        //3. 保存文件
        return FileBufferWriteToFile(L"InjectCodeByCreateNewSection1.exe");
    }

    //扩大节区
    BOOL ExpandSection(DWORD ExSize) {
        //扩大节区大小是针对ImageBuffer而言的,所以我们添加的大小要进行内存对齐

        //1. 申请一块新空间
        ExpandFileBuffer(ExSize);       //注意这个节表指针要在申请新空间之后
        PIMAGE_SECTION_HEADER pLastSectionHeader = &pSectionHeader[numberOfSections - 1];//只能扩大最后一个节区

        //2. 调整SizeOfImage
        //如果VirtualSize+ExSize超过了AlignSize(VirtualSize,0x1000) 那么需要调整,否则不需要改变
        //例如vs=0x500 ex=0x400 显然,原始vs内存对齐也会占0x1000 扩展后没有超过0x1000
        //取文件大小和内存大小的最大值

        //先计算扩展后的内存对齐值和扩展前的内存对齐值之间的差值
        DWORD AlignExImage = AlignSize(pLastSectionHeader->Misc.VirtualSize + ExSize, 0x1000) -
            AlignSize(max(pLastSectionHeader->Misc.VirtualSize, pLastSectionHeader->SizeOfRawData), 0x1000);//内存对齐后的值
        if (AlignExImage > 0)//如果差值>0说明需要扩展映像 否则内存对齐的空白区足够存储扩展区
            pOptionalHeader->SizeOfImage = sizeOfImage = sizeOfImage + AlignExImage;

        //3. 修改文件大小和内存大小 注意要在修改sizeofimage后再更新这两个值
        pLastSectionHeader->SizeOfRawData += AlignSize(ExSize, 0x200);//文件大小必须是文件对齐整数倍
        pLastSectionHeader->Misc.VirtualSize += ExSize;//由于是内存对齐前的大小,所以直接加上文件对齐后的大小即可

        //4. 保存文件
        return FileBufferWriteToFile(L"ExpandSectionFile.exe");
    }

    //合并所有节区为1个 
    BOOL CombineSection() {
        //1. 直接修改ImageBuffer
        PIMAGE_DOS_HEADER pDosHeaderOfImage = (PIMAGE_DOS_HEADER)imageBuffer;
        PIMAGE_NT_HEADERS pNtHeadersOfImage = (PIMAGE_NT_HEADERS)(imageBuffer + pDosHeader->e_lfanew);
        PIMAGE_FILE_HEADER pFileHeaderOfImage = (PIMAGE_FILE_HEADER)(&pNtHeadersOfImage->FileHeader);
        PIMAGE_OPTIONAL_HEADER pOptionalHeaderOfImage = (PIMAGE_OPTIONAL_HEADER)(&pNtHeadersOfImage->OptionalHeader);
        PIMAGE_SECTION_HEADER pSectionHeaderOfImage = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeaderOfImage + pFileHeaderOfImage->SizeOfOptionalHeader);

        //复制节区属性
        for (DWORD i = 1; i < numberOfSections; i++) {
            pSectionHeaderOfImage[0].Characteristics |= pSectionHeaderOfImage[i].Characteristics;
        }
        //调整节表
        pSectionHeaderOfImage[0].PointerToRawData = pSectionHeaderOfImage[0].VirtualAddress;//文件偏移改为内存偏移
        pSectionHeaderOfImage[0].Misc.VirtualSize = pSectionHeaderOfImage[0].SizeOfRawData = sizeOfImage - pSectionHeaderOfImage[0].VirtualAddress;//新的节区大小为所有节区内存大小之和
        pOptionalHeaderOfImage->SizeOfHeaders = AlignSize(sizeOfHeaders - (numberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER), 0x200);//调整头大小
        //删除其他节表
        memset(&pSectionHeaderOfImage[1], 0, sizeof(IMAGE_SECTION_HEADER) * (numberOfSections - 1));
        pFileHeaderOfImage->NumberOfSections = 1;
        return ImageBufferWriteToFile(L"CombineSection1.exe");
    }

    ~PEFile() {
        if (FileBuffer)          //释放空间
            delete[] FileBuffer;
        if (imageBuffer)
            delete[] imageBuffer;
        if (hProcess)
            CloseHandle(hProcess);
    }
};
int main() {
    //PEFile peFile = PEFile(L"C:\\Users\\admin\\Desktop\\DailyExercise.exe");
    PEFile peFile = PEFile(L"C:\\Users\\admin\\Desktop\\DllTest.dll");
    peFile.showPeFile();
    return 0;
}
