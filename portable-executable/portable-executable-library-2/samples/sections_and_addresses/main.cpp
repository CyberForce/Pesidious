#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как работать с секциями в PE-файле
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: sections_and_addresses.exe PE_FILE" << std::endl;
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

		//Выведем имя секции, в которой находится точка входа PE-файла
		//В хитрых PE-файлах точка входа может находиться в заголовке, тогда section_from_rva бросит исключение
		std::cout << "EP section name: " << image.section_from_rva(image.get_ep()).get_name() << std::endl;
		//Длина "сырых" (raw) данных секции
		std::cout << "EP section data length: " << image.section_data_length_from_rva(image.get_ep()) << std::endl;

		//Если у PE-файла есть импорты, выведем имя секции, в которой они находятся
		if(image.has_imports())
			std::cout << "Import section name: " << image.section_from_directory(pe_win::image_directory_entry_import).get_name() << std::endl;
	}
	catch(const pe_exception& e)
	{
		//Если возникла ошибка
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
