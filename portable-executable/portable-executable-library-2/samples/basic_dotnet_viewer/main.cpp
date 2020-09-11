#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как получить базовую информацию о .NET PE-файле
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: basic_dotnet_viewer.exe PE_FILE" << std::endl;
		return 0;
	}

	//Открываем файл
	std::ifstream pe_file(argv[1], std::ios::in | std::ios::binary);
	if(!pe_file)
	{
		std::cout << "Cannot open " << argv[1] << std::endl;
		return -1;
	}

	try
	{
		//Создаем экземпляр PE или PE+ класса с помощью фабрики
		pe_base image(pe_factory::create_pe(pe_file));

		//Если образ не .NET, выходим
		if(!image.is_dotnet())
		{
			std::cout << "Image is not .NET" << std::endl;
			return 0;
		}
		
		std::cout << "Reading basic dotnet info..." << std::hex << std::showbase << std::endl << std::endl;
		
		//Получаем .NET-заголовок PE-файла
		const basic_dotnet_info info(get_basic_dotnet_info(image));

		//Выводим некоторую информацию
		std::cout << "Major runtime version: " << info.get_major_runtime_version() << std::endl //Версия рантайма
			<< "Minor runtime version: " << info.get_minor_runtime_version() << std::endl
			<< "Flags: " << info.get_flags() << std::endl //Флаги
			<< "RVA of resources: " << info.get_rva_of_resources() << std::endl //RVA ресурсов
			<< "RVA of metadata: " << info.get_rva_of_metadata() << std::endl //RVA метаданных
			<< "Size of resources: " << info.get_size_of_resources() << std::endl //Размер ресурсов
			<< "Size of metadata: " << info.get_size_of_metadata() << std::endl; //Размер метаданных

		//Определим точку входа .NET
		if(info.is_native_entry_point())
			std::cout << "Entry point RVA: ";
		else
			std::cout << "Entry point token: ";

		std::cout << info.get_entry_point_rva_or_token() << std::endl;
	}
	catch(const pe_exception& e)
	{
		//Если возникла ошибка
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
