#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как добавить новый импорт в таблицу импорта PE-файла
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: import_adder.exe PE_FILE" << std::endl;
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

		//Получим список импортируемых библиотек и функций
		imported_functions_list imports(get_imported_functions(image));

		//Создадим новую библиотеку, из которой будем импортировать функции
		import_library new_lib;
		new_lib.set_name("kaimi_dx.dll"); //Пусть это будет kaimi_dx.dll

		//Добавим к ней пару импортов функций
		imported_function func;
		func.set_name("Tralala"); //Один импорт - по имени Tralala
		func.set_iat_va(0x1); //Запишем ненулевой абсолютный адрес в import address table

		imported_function func2;
		func2.set_ordinal(5); //Другой импорт - по ординалу 5
		func2.set_iat_va(0x2); //Запишем ненулевой абсолютный адрес в import address table

		//Мы указали некорректное содержимое (0x1 и 0x2) для ячеек, в которые будут записаны адреса импортируемых функций
		//Это не имеет значения в общем случае, потому что эти значения всегда переписываются загрузчиком
		//Эти адреса важны только в том случае, если exe-файл имеет привязанный импорт

		//Добавим импорты
		new_lib.add_import(func);
		new_lib.add_import(func2);
		imports.push_back(new_lib); //Добавим импортированную библиотеку к импортам

		//Можно редактировать и существующие импорты

		//Но мы просто пересоберем таблицу импортов
		//Она будет иметь больший размер, чем до нашего редактирования,
		//поэтому запишем ее в новую секцию, чтобы все поместилось
		//(мы не можем расширять существующие секции, если только секция не в самом конце файла)
		section new_imports;
		new_imports.get_raw_data().resize(1); //Мы не можем добавлять пустые секции, поэтому пусть у нее будет начальный размер данных 1
		new_imports.set_name("new_imp"); //Имя секции
		new_imports.readable(true).writeable(true); //Доступна на чтение и запись
		section& attached_section = image.add_section(new_imports); //Добавим секцию и получим ссылку на добавленную секцию с просчитанными размерами

		//Структура, отвечающая за настройки пересборщика импортов
		import_rebuilder_settings settings(true, false); //Модифицируем заголовок PE и не очищаем поле IMAGE_DIRECTORY_ENTRY_IAT
		rebuild_imports(image, imports, attached_section, settings); //Пересобираем импорты

		//Создаем новый PE-файл
		std::string base_file_name(argv[1]);
		std::string::size_type slash_pos;
		if((slash_pos = base_file_name.find_last_of("/\\")) != std::string::npos)
			base_file_name = base_file_name.substr(slash_pos + 1);

		base_file_name = "new_" + base_file_name;
		std::ofstream new_pe_file(base_file_name.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
		if(!new_pe_file)
		{
			std::cout << "Cannot create " << base_file_name << std::endl;
			return -1;
		}

		//Пересобираем PE-файл
		rebuild_pe(image, new_pe_file);

		std::cout << "PE was rebuilt and saved to " << base_file_name << std::endl;
	}
	catch(const pe_exception& e)
	{
		//Если возникла ошибка
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
