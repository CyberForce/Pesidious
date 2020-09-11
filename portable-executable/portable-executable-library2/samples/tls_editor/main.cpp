#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как редактировать TLS (Thread Local Storage) у PE-файлов
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: tls_editor.exe PE_FILE" << std::endl;
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

		//Получим информацию о TLS PE-файла
		//Если TLS нет, этот вызов выбросит исключение
		tls_info info(get_tls_info(image));
		
		//Пересоберем TLS
		//Он, вероятно, будет иметь больший размер, чем до нашего редактирования,
		//поэтому запишем его в новую секцию, чтобы все поместилось
		//(мы не можем расширять существующие секции, если только секция не в самом конце файла)
		section new_tls;
		new_tls.get_raw_data().resize(1); //Мы не можем добавлять пустые секции, поэтому пусть у нее будет начальный размер данных 1
		new_tls.set_name("new_tls"); //Имя секции
		new_tls.readable(true); //Доступна на чтение
		section& attached_section = image.add_section(new_tls); //Добавим секцию и получим ссылку на добавленную секцию с просчитанными размерами

		if(info.get_callbacks_rva() != 0) //Если у TLS есть хотя бы один коллбек
			info.add_tls_callback(0x100); //Добавим новый коллбек в TLS - относительный адрес, скорее всего, некорректен, поэтому программа не запустится (просто для примера)

		info.set_raw_data("Hello, world!"); //Установим или заменим "сырые" данные TLS
		info.set_raw_data_start_rva(image.rva_from_section_offset(attached_section, 0)); //Расположим их с начала добавленной секции
		info.recalc_raw_data_end_rva(); //Просчитаем новый конечный адрес "сырых" данных

		//Пересобираем TLS, расположив их с 50-го байта (будет выровнено, секция будет автоматически расширена) новой секции и записав новые данные TLS в PE-заголовок
		//По умолчанию функция пересобирает также TLS-коллбеки и "сырые" данные TLS, располагая их по указанным в структуре info адресам
		//Опция expand позволяет задать, как должны распологаться "сырые" данные
		//tls_data_expand_raw позволяет увеличить "сырой" размер секции, то есть размер в файле
		//tls_data_expand_virtual позволяет увеличить виртуальный размер секции с данными TLS
		//Если не хватит места под данные TLS, будет записана только их часть, или вообще ничего записано не будет
		rebuild_tls(image, info, attached_section, 50); 

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
