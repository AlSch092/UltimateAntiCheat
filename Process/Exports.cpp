#include "Exports.hpp"

bool Exports::ChangeFunctionName(string dllName, string functionName, string newName)
{
	bool result = false;
	DWORD oldProt = 0;

	string sName;
	DWORD* dNameRVAs(0); //addresses of export names
	_IMAGE_EXPORT_DIRECTORY* ImageExportDirectory;
	unsigned long cDirSize;
	_LOADED_IMAGE LoadedImage;

	if (MapAndLoad(dllName.c_str(), NULL, &LoadedImage, TRUE, TRUE))
	{
		if (LoadedImage.MappedAddress == 0)
		{
			printf("[ERROR] LoadedImage.MappedAddress was 0 at ChangeFunctionName!\n");
			return false;
		}

		ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);

		if (ImageExportDirectory != NULL)
		{
			//load list of function names from DLL, the third parameter is an RVA to the data we want
			dNameRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNames, NULL);

			for (size_t i = 0; i < ImageExportDirectory->NumberOfNames; i++)
			{
				//get RVA 
				sName = (char*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dNameRVAs[i], NULL);

				if (strcmp(functionName.c_str(), sName.c_str()) == 0)
				{
					UINT64 funcName_Address = (UINT64)GetModuleHandleA(dllName.c_str()) + dNameRVAs[i]; //get address of symbol

					if (!VirtualProtect((LPVOID)funcName_Address, 1024, PAGE_EXECUTE_READWRITE, &oldProt))				
						printf("VirtualProtect failed: %d\n", GetLastError());				
					else
					{
						strcpy_s((char*)funcName_Address, strlen((char*)funcName_Address) + 1, newName.c_str()); //if you're writing more bytes over than the original strings length, you need to expand + shuffle the entire symbol list's memory appropriately and potentially update any offsets.
						result = true; //successful case
					}
				}
			}
		}
	}

	UnMapAndLoad(&LoadedImage);
	return true;
}