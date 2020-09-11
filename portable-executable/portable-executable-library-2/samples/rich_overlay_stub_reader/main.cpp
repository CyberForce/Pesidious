#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как получить информацию о стабе PE-файла и rich overlay, который добавляет при компиляции MS Visual Studio
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: rich_overlay_stub_reader.exe PE_FILE" << std::endl;
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

		//Выведем длину DOS stub'а
		std::cout << "Image stub length: " << image.get_stub_overlay().length() << std::endl << std::endl;

		//Перечисляем все RICH-записи
		rich_data_list data = get_rich_data(image);
		for(rich_data_list::const_iterator it = data.begin(); it != data.end(); ++it)
		{
			//Выводим информацию о записи
			std::cout << "Number: " << (*it).get_number() << std::endl
				<< "Times: " << (*it).get_times() << std::endl
				<< "Version: " << (*it).get_version() << std::endl
				<< std::endl;
		}

		//Отобразим информацию о том, есть ли у файла оверлей в конце (у некоторых инсталляторов, например, есть)
		std::cout << "Has overlay in the end: " << (image.has_overlay() ? "YES" : "NO") << std::endl;
	}
	catch(const pe_exception& e)
	{
		//Если возникла ошибка
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
