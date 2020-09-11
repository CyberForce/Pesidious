#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как добавить новую релокацию в таблицы релокаций PE-файла
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: relocation_adder.exe PE_FILE" << std::endl;
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

		//Перечислим и получим все записи из таблиц релокаций в PE-файле, кроме абсолютных
		//Можно было бы включить в список и абсолютные записи (ABSOLUTE), передав в вызов true
		//Эти записи не нужны при пересборке релокаций, они используются для выравнивания
		//и будут добавлены автоматически пересборщиком
		relocation_table_list tables(get_relocations(image));
		
		//Создаем новую таблицу релокаций
		relocation_table new_table;
		new_table.set_rva(0x5678); //Относительный адрес релокаций в таблице - он некорректен, для примера, поэтому получившийся PE скорее всего не загрузится
		//Добавим в таблицу новую релокацию
		new_table.add_relocation(relocation_entry(10, 3)); //Тип 3 - HIGHLOW-релокация, RRVA = 10, т.е. RVA = 0x5678 + 10
		//Добавляем таблицу
		tables.push_back(new_table);

		//Можно редактировать и существующие релокации, но делать этого не стоит, так как файл не загрузится, если что-то в них поменять
		//Если их удалить у EXE-файла полностью, то все будет нормально, у DLL этого делать не стоит
		//Мы просто пересоберем релокации
		//Они будет иметь больший размер, чем до нашего редактирования,
		//поэтому запишем их в новую секцию, чтобы все поместилось
		//(мы не можем расширять существующие секции, если только секция не в самом конце файла)
		section new_relocs;
		new_relocs.get_raw_data().resize(1); //Мы не можем добавлять пустые секции, поэтому пусть у нее будет начальный размер данных 1
		new_relocs.set_name("new_rel"); //Имя секции
		new_relocs.readable(true); //Доступна на чтение
		section& attached_section = image.add_section(new_relocs); //Добавим секцию и получим ссылку на добавленную секцию с просчитанными размерами

		rebuild_relocations(image, tables, attached_section); //Пересобираем экспорты, расположив их с начала новой секции и записав новые данные таблиц релокаций в PE-заголовок

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
