#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как добавить новый экспорт в таблицу экспорта PE-файла
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: export_adder.exe PE_FILE" << std::endl;
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

		//Получим список экспортируемых функций и информацию об экспорте
		export_info info;
		exported_functions_list exports;

		//Если экспортов у файла нет, этот вызов бросит исключение, но это не значит, что мы
		//не можем создать таблицу экспортов с нуля
		try
		{
			exports = get_exported_functions(image, info);
		}
		catch(const pe_exception&)
		{
			//Нет таблицы экспортов, или она кривая
			//Создадим информацию об экспортах вручную
			info.set_name("MySuperLib.dll");
			info.set_ordinal_base(5);
		}

		//Создаем новую экспортируемую функцию
		exported_function func;
		func.set_name("SuperKernelCall"); //Имя экспортируемой функции
		func.set_rva(0x123); //Относительный адрес точки входа экспортируемой функции (некорректный, чисто для примера)

		//Необходимо вычислить ординал функции, которую мы добавляем, чтобы не было повторных
		//Для этого есть вспомогательная функция
		func.set_ordinal(get_export_ordinal_limits(exports).second + 1); //Сделаем наш ординал = максимальный ординал среди существующих экспортов + 1
		exports.push_back(func); //Добавим функцию к экспортам
		
		//Можно редактировать и существующие экспорты
		//или изменить информацию об экспортах (info)
		//Но мы просто пересоберем таблицу экспортов
		//Она будет иметь больший размер, чем до нашего редактирования,
		//поэтому запишем ее в новую секцию, чтобы все поместилось
		//(мы не можем расширять существующие секции, если только секция не в самом конце файла)
		section new_exports;
		new_exports.get_raw_data().resize(1); //Мы не можем добавлять пустые секции, поэтому пусть у нее будет начальный размер данных 1
		new_exports.set_name("new_exp"); //Имя секции
		new_exports.readable(true); //Доступна на чтение
		section& attached_section = image.add_section(new_exports); //Добавим секцию и получим ссылку на добавленную секцию с просчитанными размерами

		rebuild_exports(image, info, exports, attached_section); //Пересобираем экспорты, расположив их с начала новой секции и записав новые данные таблиц экспорта в PE-заголовок

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
