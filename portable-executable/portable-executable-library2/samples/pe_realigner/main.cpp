#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как изменить файловое выравнивание PE-файлов
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: pe_realigner.exe PE_FILE" << std::endl;
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
		
		//Выведем темущий file alignment
		std::cout << "File alignment: " << image.get_file_alignment() << std::endl;
		
		//Предложим выбрать новое выравнивание
		unsigned int new_alignment_index = static_cast<unsigned int>(-1);

		while(new_alignment_index > 3)
		{
			if(std::cin.fail())
			{
				//На случай, если пользователь ввел что-то некорректное
				std::cin.clear();
				std::cin.ignore(static_cast<std::streamsize>(-1), '\n');
			}

			std::cout << "Choose new file alignment" << std::endl;
			std::cout << "(0 = 512, 1 = 1024, 2 = 2048, 3 = 4096): ";
			std::cin >> new_alignment_index;
		}
		
		unsigned int available_aligns[] = {512, 1024, 2048, 4096};

		//Изменим выравнивание на то, которое указал пользователь
		image.realign_file(available_aligns[new_alignment_index]);

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
