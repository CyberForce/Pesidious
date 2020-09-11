#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как считать и получить информацию о директории исключений
//Она существует только для 64-разрядных PE-файлов (PE+)
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: exception_dir_reader.exe PE_FILE" << std::endl;
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
		
		//Проверим, есть ли директория информации об исключениях у PE-файла
		if(!image.has_exception_directory())
		{
			std::cout << "Image has no exception directory" << std::endl;
			return 0;
		}

		std::cout << "Reading exception directory..." << std::hex << std::showbase << std::endl << std::endl;
		
		//Получаем информацию из exception directory
		const exception_entry_list info(get_exception_directory_data(image));

		//Выведем записи из exception directory
		//Подробное описание всех этих структур есть в MSDN
		for(exception_entry_list::const_iterator it = info.begin(); it != info.end(); ++it)
		{
			const exception_entry& entry = *it; //Запись из таблицы

			//Выведем информацию
			std::cout << "Addresses: [" << entry.get_begin_address() << ":" << entry.get_end_address() << "]:" << std::endl
				<< "Flags: " << static_cast<unsigned long>(entry.get_flags()) << std::endl
				<< "Frame pointer register number: " << static_cast<unsigned long>(entry.get_frame_pointer_register_number()) << std::endl
				<< "Number of unwind slots: " << static_cast<unsigned long>(entry.get_number_of_unwind_slots()) << std::endl
				<< "Scaled RSP offset: " << static_cast<unsigned long>(entry.get_scaled_rsp_offset()) << std::endl
				<< "Size of prolog: " << static_cast<unsigned long>(entry.get_size_of_prolog()) << std::endl
				<< "Unwind info address: " << entry.get_unwind_info_address() << std::endl
				<< "Unwind info version: " << static_cast<unsigned long>(entry.get_unwind_info_version()) << std::endl
				<< std::endl;
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
