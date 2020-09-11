#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как считать и получить информацию об импортах PE или PE+ файла
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: imports_reader.exe PE_FILE" << std::endl;
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
		
		//Проверим, есть ли импорты у файла
		if(!image.has_imports())
		{
			std::cout << "Image has no imports" << std::endl;
			return 0;
		}

		std::cout << "Reading PE imports..." << std::hex << std::showbase << std::endl << std::endl;

		//Получаем список импортируемых библиотек с функциями
		const imported_functions_list imports = get_imported_functions(image);

		//Перечисляем импортированные библиотеки и выводим информацию о них
		for(imported_functions_list::const_iterator it = imports.begin(); it != imports.end(); ++it)
		{
			const import_library& lib = *it; //Импортируемая библиотека
			std::cout << "Library [" << lib.get_name() << "]" << std::endl //Имя
				<< "Timestamp: " << lib.get_timestamp() << std::endl //Временная метка
				<< "RVA to IAT: " << lib.get_rva_to_iat() << std::endl //Относительный адрес к import address table
				<< "========" << std::endl;

			//Перечисляем импортированные функции для библиотеки
			const import_library::imported_list& functions = lib.get_imported_functions();
			for(import_library::imported_list::const_iterator func_it = functions.begin(); func_it != functions.end(); ++func_it)
			{
				const imported_function& func = *func_it; //Импортированная функция
				std::cout << "[+] ";
				if(func.has_name()) //Если функция имеет имя - выведем его
					std::cout << func.get_name();
				else
					std::cout << "#" << func.get_ordinal(); //Иначе она импортирована по ординалу

				//Хинт
				std::cout << " hint: " << func.get_hint() << std::endl;
			}

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
