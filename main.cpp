#include <windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include <Psapi.h>
#include <algorithm>
#include <string>
#include <locale>
#include <codecvt>

// Конвертер строки в wstring
std::wstring string_to_wstring(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(str);
}

// Получение ID процесса по имени
DWORD GetProcessID(const wchar_t* processName) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32FirstW(snapshot, &entry)) {
        while (Process32NextW(snapshot, &entry)) {
            if (!wcscmp(entry.szExeFile, processName)) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }
    CloseHandle(snapshot);
    return 0;
}

// Сканирование памяти процесса
std::vector<uintptr_t> ScanMemory(HANDLE processHandle, const void* targetData, size_t dataSize) {
    std::vector<uintptr_t> results;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORY_BASIC_INFORMATION memInfo;
    uint8_t* address = (uint8_t*)sysInfo.lpMinimumApplicationAddress;
    uint8_t* buffer = new uint8_t[dataSize];

    while (address < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(processHandle, address, &memInfo, sizeof(memInfo))) {
            if (memInfo.State == MEM_COMMIT && memInfo.Protect != PAGE_NOACCESS) {
                uint8_t* region = new uint8_t[memInfo.RegionSize];
                SIZE_T bytesRead;

                if (ReadProcessMemory(processHandle, memInfo.BaseAddress, region, memInfo.RegionSize, &bytesRead)) {
                    for (size_t i = 0; i < bytesRead - dataSize; i++) {
                        if (memcmp(region + i, targetData, dataSize) == 0) {
                            results.push_back((uintptr_t)memInfo.BaseAddress + i);
                        }
                    }
                }
                delete[] region;
            }
            address += memInfo.RegionSize;
        }
        else {
            address += sysInfo.dwPageSize;
        }
    }
    delete[] buffer;
    return results;
}

// Функция для записи в память
bool WriteMemory(HANDLE processHandle, uintptr_t address, const void* value, size_t size) {
    DWORD oldProtect;
    // Изменяем защиту памяти на запись
    if (!VirtualProtectEx(processHandle, (LPVOID)address, size, PAGE_READWRITE, &oldProtect)) {
        std::cerr << "Ошибка изменения защиты памяти (Error: " << GetLastError() << ")" << std::endl;
        return false;
    }

    SIZE_T bytesWritten;
    BOOL result = WriteProcessMemory(processHandle, (LPVOID)address, value, size, &bytesWritten);

    // Восстанавливаем оригинальную защиту
    VirtualProtectEx(processHandle, (LPVOID)address, size, oldProtect, &oldProtect);

    if (!result || bytesWritten != size) {
        std::cerr << "Ошибка записи в память (Error: " << GetLastError() << ")" << std::endl;
        return false;
    }
    return true;
}

// Функция для поиска общих адресов среди всех сканирований
std::vector<uintptr_t> FindCommonAddresses(HANDLE processHandle) {
    std::vector<std::vector<uintptr_t>> allAddresses;
    int targetValue;
    char continueScanning;

    do {
        // Запрос значения для поиска
        std::cout << "Введите значение для поиска: ";
        std::cin >> targetValue;

        // Сканирование памяти
        auto addresses = ScanMemory(processHandle, &targetValue, sizeof(targetValue));
        std::cout << "Найдено " << addresses.size() << " совпадений для значения " << targetValue << ":" << std::endl;
        for (uintptr_t addr : addresses) {
            std::cout << "0x" << std::hex << addr << std::dec << std::endl;
        }

        // Сохраняем результаты сканирования
        allAddresses.push_back(addresses);

        // Запрос на продолжение
        std::cout << "Продолжить сканирование? (y/n): ";
        std::cin >> continueScanning;
    } while (continueScanning == 'y' || continueScanning == 'Y');

    // Если было менее 2 сканирований, возвращаем пустой список
    if (allAddresses.size() < 2) {
        return {};
    }

    // Находим пересечение всех списков адресов
    std::vector<uintptr_t> commonAddresses = allAddresses[0];

    for (size_t i = 1; i < allAddresses.size(); ++i) {
        std::vector<uintptr_t> tempCommon;
        std::sort(commonAddresses.begin(), commonAddresses.end());
        std::sort(allAddresses[i].begin(), allAddresses[i].end());

        std::set_intersection(
            commonAddresses.begin(), commonAddresses.end(),
            allAddresses[i].begin(), allAddresses[i].end(),
            std::back_inserter(tempCommon)
        );

        commonAddresses = std::move(tempCommon);

        if (commonAddresses.empty()) {
            break; // Нет общих адресов
        }
    }

    return commonAddresses;
}

// Функция для модификации значений в памяти
void ModifyMemoryValues(HANDLE processHandle, const std::vector<uintptr_t>& addresses) {
    std::cout << "\n=== Режим модификации памяти ===" << std::endl;

    for (uintptr_t addr : addresses) {
        std::cout << "\nАдрес: 0x" << std::hex << addr << std::dec << std::endl;

        // Чтение текущего значения
        int currentValue;
        if (ReadProcessMemory(processHandle, (LPCVOID)addr, &currentValue, sizeof(currentValue), NULL)) {
            std::cout << "Текущее значение: " << currentValue << std::endl;

            // Запрос на изменение
            std::cout << "Изменить значение? (y/n): ";
            char choice;
            std::cin >> choice;

            if (choice == 'y' || choice == 'Y') {
                int newValue;
                std::cout << "Введите новое значение: ";
                std::cin >> newValue;

                // Запись нового значения
                if (WriteMemory(processHandle, addr, &newValue, sizeof(newValue))) {
                    std::cout << "Значение успешно изменено!" << std::endl;

                    // Проверка записи
                    int verifyValue;
                    if (ReadProcessMemory(processHandle, (LPCVOID)addr, &verifyValue, sizeof(verifyValue), NULL)) {
                        std::cout << "Проверочное значение: " << verifyValue << std::endl;
                    }
                }
            }
        }
        else {
            std::cerr << "Ошибка чтения памяти по адресу 0x" << std::hex << addr << std::dec << std::endl;
        }
    }
}

int main() {
    setlocale(LC_ALL, "russian");

    // Запрос названия процесса у пользователя
    std::string processNameStr;
    std::cout << "Введите название процесса (например: ra3ep1_1.0.game): ";
    std::getline(std::cin, processNameStr);

    // Конвертация в wchar_t*
    std::wstring processNameWstr = string_to_wstring(processNameStr);
    const wchar_t* processName = processNameWstr.c_str();

    DWORD processID = GetProcessID(processName);

    if (!processID) {
        std::wcerr << L"Процесс '" << processName << L"' не найден!" << std::endl;
        return 1;
    }

    // Открываем процесс с правами на чтение и запись
    HANDLE processHandle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE,
        processID
    );

    if (!processHandle) {
        std::cerr << "Не удалось открыть процесс (Error: " << GetLastError() << ")" << std::endl;
        return 1;
    }

    // Находим общие адреса
    auto commonAddresses = FindCommonAddresses(processHandle);

    // Выводим результаты
    std::cout << "\nОбщие адреса во всех сканированиях: " << commonAddresses.size() << std::endl;
    for (uintptr_t addr : commonAddresses) {
        std::cout << "0x" << std::hex << addr << std::dec << std::endl;

        // Дополнительная проверка текущего значения по адресу
        int currentValue;
        if (ReadProcessMemory(processHandle, (LPCVOID)addr, &currentValue, sizeof(currentValue), NULL)) {
            std::cout << "  Текущее значение: " << currentValue << std::endl;
        }
    }

    // Предлагаем изменить значения в памяти
    if (!commonAddresses.empty()) {
        std::cout << "\nХотите изменить значения в найденных адресах? (y/n): ";
        char modifyChoice;
        std::cin >> modifyChoice;

        if (modifyChoice == 'y' || modifyChoice == 'Y') {
            ModifyMemoryValues(processHandle, commonAddresses);
        }
    }

    CloseHandle(processHandle);
    return 0;
}
