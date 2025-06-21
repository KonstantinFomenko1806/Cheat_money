#include <windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include <algorithm>
#include <string>
#include <codecvt>

char dialog;

HANDLE Get_Descriptor() //Функция получения дескриптора указанного процесса
{
    std::string processNameStr;
    std::cout << "Введите название процесса (например: ra3ep1_1.0.game): ";
    std::getline(std::cin >> std::ws, processNameStr);

    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;   //Преобразование переменной
    std::wstring processNameWstr = converter.from_bytes(processNameStr);
    const wchar_t* processName = processNameWstr.c_str();

    DWORD processID;
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32FirstW(snapshot, &entry))
    {
        while (Process32NextW(snapshot, &entry))
        {
            if (!wcscmp(entry.szExeFile, processName))
            {
                CloseHandle(snapshot);
                processID = entry.th32ProcessID;
            }
        }
    }
    else
    {
        CloseHandle(snapshot);
        std::wcerr << L"Процесс '" << processName << L"' не найден!" << std::endl;
        std::terminate();
    }

    HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, processID);

    if (!processHandle)
    {
        std::cerr << "Не удалось открыть процесс (Error: " << GetLastError() << ")" << std::endl;
        std::terminate();
    }
    return processHandle;
}

template<typename T>
bool ReadMemoryValue(HANDLE processHandle, uintptr_t address, T& outputValue)   //Функция чтения значений из памяти
{
    if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE || address == 0)
        return false;

    SIZE_T bytesRead;
    return ReadProcessMemory(processHandle, (LPCVOID)address,
        &outputValue, sizeof(T), &bytesRead)
        && bytesRead == sizeof(T);
}

void InteractiveReadMemory()   // Функция чтения значения из памяти с интерфейсом пользователя
{
    HANDLE processHandle = Get_Descriptor();
    uintptr_t address;

    std::cout << "Введите адрес (hex): 0x";
    std::cin >> std::hex >> address >> std::dec;

    int value;
    if (ReadMemoryValue(processHandle, address, value)) std::cout << "Значение: " << value << std::endl;
    else std::cerr << "Ошибка чтения" << std::endl;
    system("pause");
}

void WriteMem() //Функция записи значения в память
{
    uintptr_t address;
    HANDLE processHandle = Get_Descriptor();

    std::cout << "Введите адрес в шестнадцатеричном формате (например, 7FFE1E192590): 0x";
    std::cin >> std::hex >> address >> std::dec;

    int newValue;
    std::cout << "Введите новое значение: ";
    std::cin >> newValue;
    
    DWORD oldProtect;
    if (!VirtualProtectEx(processHandle, (LPVOID)address, sizeof(newValue), PAGE_READWRITE, &oldProtect))
    {
        std::cerr << "Ошибка изменения защиты памяти (Error: " << GetLastError() << ")" << std::endl;
        return;
    }

    SIZE_T bytesWritten;
    BOOL result = WriteProcessMemory(processHandle, (LPVOID)address, &newValue, sizeof(newValue), &bytesWritten);

    VirtualProtectEx(processHandle, (LPVOID)address, sizeof(newValue), oldProtect, &oldProtect);

    if (!result || bytesWritten != sizeof(newValue))
    {
        std::cerr << "Ошибка записи в память (Error: " << GetLastError() << ")" << std::endl;
        return;
    }
    
    int verifyValue;
    std::cout << "Значение успешно изменено!" << std::endl;
    if (ReadMemoryValue(processHandle, address, verifyValue)) std::cout << "Проверочное значение: " << verifyValue << std::endl;
}

void ScanMem() //Функция поиска адреса памяти с указанным значением  
{
    std::vector<std::vector<uintptr_t>> allAddresses;
    std::vector<uintptr_t> commonAddresses;
    char continueScanning;
    int targetValue;

    HANDLE processHandle = Get_Descriptor();
   
    do
    {
        std::cout << "Введите значение для поиска: ";
        std::cin >> targetValue;

        std::vector<uintptr_t> results;
        std::vector<uintptr_t> addresses;
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        MEMORY_BASIC_INFORMATION memInfo;
        uint8_t* address = (uint8_t*)sysInfo.lpMinimumApplicationAddress;
            
        uint8_t* buffer = new uint8_t[targetValue];

        while (address < sysInfo.lpMaximumApplicationAddress)
        {
            if (VirtualQueryEx(processHandle, address, &memInfo, sizeof(memInfo)))
            {
                if (memInfo.State == MEM_COMMIT && memInfo.Protect != PAGE_NOACCESS)
                {
                    uint8_t* region = new uint8_t[memInfo.RegionSize];
                    SIZE_T bytesRead;

                    if (ReadProcessMemory(processHandle, memInfo.BaseAddress, region, memInfo.RegionSize, &bytesRead))
                    {
                        for (size_t i = 0; i < bytesRead - sizeof(targetValue); i++)
                        {
                            if (memcmp(region + i, &targetValue, sizeof(targetValue)) == 0) addresses.push_back((uintptr_t)memInfo.BaseAddress + i);
                        }
                    }
                    delete[] region;
                }
                address += memInfo.RegionSize;
            }
            else address += sysInfo.dwPageSize;
        }
        delete[] buffer;
           
        std::cout << "Найдено " << addresses.size() << " совпадений для значения " << targetValue << ":" << std::endl;
        for (uintptr_t addr : addresses) std::cout << "0x" << std::hex << addr << std::dec << std::endl;
        allAddresses.push_back(addresses);

        std::cout << "Продолжить сканирование? (y/n): ";
        std::cin >> continueScanning;
    } while (continueScanning == 'y' || continueScanning == 'Y');

    commonAddresses = allAddresses[0];

    for (size_t i = 1; i < allAddresses.size(); ++i)
    {
        std::vector<uintptr_t> tempCommon;
        std::sort(commonAddresses.begin(), commonAddresses.end());
        std::sort(allAddresses[i].begin(), allAddresses[i].end());
        std::set_intersection(
        commonAddresses.begin(), commonAddresses.end(),
        allAddresses[i].begin(), allAddresses[i].end(),
        std::back_inserter(tempCommon));
        commonAddresses = std::move(tempCommon);
        if (commonAddresses.empty()) break;
    }
    
    std::cout << "\nОбщие адреса во всех сканированиях: " << commonAddresses.size() << std::endl;
    for (uintptr_t addr : commonAddresses)
    {
        int currentValue;
        std::cout << "0x" << std::hex << addr << std::dec << std::endl;
        if (ReadMemoryValue(processHandle, addr, currentValue)) std::cout << "  Текущее значение: " << currentValue << std::endl;
    }
    system("pause");
}

int main()
{
    setlocale(LC_ALL, "Russian");

    while (true) //меню
    {
        std::cout << "1 - Поиск адреса в памяти по указанному значению;\n";
        std::cout << "2 - Чтение значения по указанному адресу в памяти;\n";
        std::cout << "3 - Записать значение по указанному адресу в памяти;\n";
        std::cout << "0 - Выйти из программы.\n";
        std::cout << "Выберите операцию: ";
        std::cin >> dialog;

        switch (dialog)
        {
        case '0': return 0;

        case '1':
        {
            ScanMem();
            break;
        }
        case '2':
        {
            InteractiveReadMemory();
            break;
        }
        case '3':
        {
            WriteMem();
            break;
        }
        }
    }
}
