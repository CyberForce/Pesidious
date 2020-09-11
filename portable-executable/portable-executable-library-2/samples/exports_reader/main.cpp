#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как считать и получить информацию об экспортах PE или PE+ файла
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: exports_reader.exe PE_FILE" << std::endl;
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

		//Проверим, есть ли экспорты у PE-файла
		if(!image.has_exports())
		{
			std::cout << "Image has no exports" << std::endl;
			return 0;
		}

		std::cout << "Reading PE exports..." << std::hex << std::showbase << std::endl << std::endl;
		
		//Получаем полную информацию об экспортах и список экспортируемых функций
		export_info info;
		const exported_functions_list exports = get_exported_functions(image, info);

		//Выведем некоторую информацию об экспорте:
		std::cout << "Export info" << std::endl
			<< "Library name: " << info.get_name() << std::endl //Имя библиотеки
			<< "Timestamp: " << info.get_timestamp() << std::endl //Временная метка
			<< "Ordinal base: " << info.get_ordinal_base() << std::endl //База ординалов
			<< std::endl;

		//Перечисляем секции и выводим информацию о них
		for(exported_functions_list::const_iterator it = exports.begin(); it != exports.end(); ++it)
		{
			const exported_function& func = *it; //Экспортируемая функция
			std::cout << "[+] ";
			if(func.has_name()) //Если функция имеет имя, выведем его и ординал имени
				std::cout << func.get_name() << ", name ordinal: " << func.get_name_ordinal() << " ";

			//Ординал функции
			std::cout << "ORD: " << func.get_ordinal();
			
			//Если функция - форвард (переадресация в другую DLL), выведем имя форварда
			if(func.is_forwarded())
				std::cout << std::endl << " -> " << func.get_forwarded_name();

			std::cout << std::endl;
		}
	}
	catch(const pe_exception& e)
	{
		//Если возникла ошибка
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
