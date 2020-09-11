#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как вырезать ненужные данные из PE-файла и пересобрать его
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: pe_stripper.exe PE_FILE" << std::endl;
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
		
		//Удалим DOS stub и rich overlay
		image.strip_stub_overlay();

		//Удалим ненужные DATA_DIRECTORY (нулевые)
		//Очень малое количество линкеров умеют это делать
		image.strip_data_directories(0);

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

		//Пересобираем PE-файл с опцией сжатия DOS-header
		//Уменьшения размера это не дает, но упаковывает NT-заголовки в DOS-заголовок
		//При пересборке автоматически убираются ненужные нулевые байты в самом конце образа,
		//в результате чего размер образа становится немного меньше
		rebuild_pe(image, new_pe_file, true);
		
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
