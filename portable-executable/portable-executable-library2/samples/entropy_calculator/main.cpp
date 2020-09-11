#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как посчитать энтропию файла и секций PE
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: entropy_calculator.exe PE_FILE" << std::endl;
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
		//Считаем энтропию файла
		std::cout << "File entropy: " << entropy_calculator::calculate_entropy(pe_file) << std::endl;

		//Создаем экземпляр PE или PE+ класса с помощью фабрики
		pe_base image(pe_factory::create_pe(pe_file));

		std::cout << "Sections entropy: " << entropy_calculator::calculate_entropy(image) << std::endl; //Считаем энтропию всех секций

		//Перечисляем секции и считаем их энтропию по отдельности
		const section_list sections = image.get_image_sections();
		for(section_list::const_iterator it = sections.begin(); it != sections.end(); ++it)
		{
			if(!(*it).empty()) //Если секция не пуста - посчитаем ее энтропию
				std::cout << "Section [" << (*it).get_name() << "] entropy: " << entropy_calculator::calculate_entropy(*it) << std::endl;
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
