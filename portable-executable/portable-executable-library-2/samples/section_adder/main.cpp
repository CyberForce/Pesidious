#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как добавить секцию в PE-файл и записать в нее какие-нибудь данные
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: section_adder.exe PE_FILE" << std::endl;
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
		
		//Секцию можно добавить только после всех существующих, чтобы PE-файл не испортился
		//Создаем новую секцию
		section new_section;
		new_section.readable(true).writeable(true); //Делаем секцию доступной для чтения и записи
		new_section.set_name("kaimi.ru"); //Ставим имя секции - максимум 8 символов
		new_section.set_raw_data("Tralala"); //Устанавливаем данные секции

		//Добавляем секцию. Все адреса пересчитаются автоматически
		//Вызов вернет ссылку на уже добавленную секцию с пересчитанными адресами
		//Совсем пустую секцию к образу добавить нельзя, у нее должен быть ненулевой размер данных или виртуальный размер
		section& added_section = image.add_section(new_section);

		//Если нужно изменить виртуальный размер секции, то делается это так:
		image.set_section_virtual_size(added_section, 0x1000);
		
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
