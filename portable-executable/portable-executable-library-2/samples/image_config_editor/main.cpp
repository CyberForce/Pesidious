#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как пересобрать директорию Load Config у PE-файла
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: image_config_editor.exe PE_FILE" << std::endl;
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

		//Получим информацию о директории Load Config
		image_config_info info(get_image_config(image));

		//Но пересоберем эту директорию, расположив ее в новой секции
		section load_config;
		load_config.get_raw_data().resize(1); //Мы не можем добавлять пустые секции, поэтому пусть у нее будет начальный размер данных 1
		load_config.set_name("load_cfg"); //Имя секции
		load_config.readable(true).writeable(true); //Доступна на чтение и запись
		section& attached_section = image.add_section(load_config); //Добавим секцию и получим ссылку на добавленную секцию с просчитанными размерами

		//Если у файла была таблица SE Handler'ов
		if(info.get_se_handler_table_va())
			info.add_se_handler_rva(0x7777); //Добавим новый SE Handler в таблицу (просто для теста)

		//Если у файла не существовало таблицы Lock-префиксов, добавим ее
		//(также для теста)
		if(!info.get_lock_prefix_table_va())
			info.add_lock_prefix_rva(0x9999);

		//Пересобираем директорию Image Load Config, пересобираем таблицу Lock-префиксов, если она имелась, а также
		//таблицу SE Handler'ов, если она есть
		rebuild_image_config(image, info, attached_section, 1);

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
