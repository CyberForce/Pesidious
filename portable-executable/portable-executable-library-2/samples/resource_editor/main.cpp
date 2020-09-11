#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include <pe_bliss_resources.h>
#ifdef PE_BLISS_WINDOWS
#include "resource.h"
#include "lib.h"
#else
#define IDR_CUSTOM1 100
#endif

using namespace pe_bliss;

//Пример, показывающий, как редактировать ресурсы PE-файла
//Для начала рекомендуется ознакомиться с примером resource_viewer
//Обратите внимание, что пример корректно отработает и в x86, и в x64 варианте
int main(int argc, char* argv[])
{
	std::string pe_filename;

#ifdef PE_BLISS_WINDOWS
	//Открываем файл (сами себя)
	pe_filename = argv[0];
#else
	std::cout << "This sample needs itself to be compiled on Windows"
		<< std::endl << "Enter its filename: ";

	std::cin >> pe_filename;
#endif
	
	std::ifstream pe_file(pe_filename.c_str(), std::ios::in | std::ios::binary);
	if(!pe_file)
	{
		std::cout << "Cannot open " << pe_filename << std::endl;
		return -1;
	}

	try
	{
		//Создаем экземпляр PE или PE+ класса с помощью фабрики
		pe_base image(pe_factory::create_pe(pe_file));

		//Суть примера будет состоять в следующем:
		//В сам пример вкомпиливается иконка в директорию с именем CUSTOM
		//Иконка состоит из трех картинок разных разрешений
		//Наша задача - считать иконку из директории CUSTOM и установить ее как главную иконку exe-файла
		//Далее - удалить директорию CUSTOM
		//Наконец, добавить какую-нибудь информацию о версии к файлу

		//Проверим, есть ли ресурсы у файла
		if(!image.has_resources())
		{
			std::cout << "Image has no resources" << std::endl;
			return 0;
		}

		//Получаем корневую директорию ресурсов
		std::cout << "Reading PE resources..." << std::hex << std::showbase << std::endl << std::endl;
		resource_directory root(get_resources(image));

		//Для облегчения работы с директориями и записями ресурсов созданы вспомогательные классы
		//Этот класс позволяет извлекать из PE-файлов любые ресурсы и перезаписывать их
		//и предоставляет высокоуровневые функции для извечения иконок, курсоров, картинкок, строковых таблиц
		//и таблиц сообщений, а также информации о версии
		//и редактирования иконок, курсоров, картинок и информации о версии
		pe_resource_manager res(root);

		//Для начала убедимся, что директория CUSTOM есть
		if(!res.resource_exists(L"CUSTOM"))
		{
			std::cout << "\"CUSTOM\" resource directory does not exist" << std::endl;
			return -1;
		}

		//Получим нашу иконку из этой директории: мы знаем, что ее ID=100 и она одна в директории имен, поэтому делаем так
		//Получаем ее по нулевому индексу (можно было получить по языку, но это незачем, т.к. она единственная)
		const resource_data_info data = res.get_resource_data_by_id(L"CUSTOM", IDR_CUSTOM1);

		//Необходимо теперь добавить ее как главную иконку
		//Иконка приложения - это иконка из той группы иконок, которая следует самой первой в списке групп иконок
		//Помните, что сначала идут именованные ресурсы, а потом ресурсы с идентификаторами, и всё сортируется
		//Создадим группу иконок с именем MAIN_ICON
		resource_cursor_icon_writer(res).add_icon(data.get_data(), //Данные файла иконки
			L"MAIN_ICON", //Имя группы иконок (помните, у нас три картинки внутри иконки, они будут находиться в этой группе)
			0, //Язык - нам неважен
			resource_cursor_icon_writer::icon_place_after_max_icon_id, //Вариант расположения иконок в существующей группе - нам он неважен, так как мы создаем новую группу
			data.get_codepage(), //Сохраним исходную Codepage
			0 //Timestamp - неважен
			);
		
		//Теперь удалим уже ненужный ресурс CUSTOM
		res.remove_resource(L"CUSTOM");
		
		//Теперь создадим информацию о версии
		file_version_info file_info; //Базовая информация о файле
		file_info.set_special_build(true); //Это будет специальный билд
		file_info.set_file_os(file_version_info::file_os_nt_win32); //Система, на которой работает файл
		file_info.set_file_version_ms(0x00010002); //Версия файла будет 1.2.3.4
		file_info.set_file_version_ls(0x00030004);

		//Теперь создадим строки с информацией и трансляции (переводы)
		lang_string_values_map strings;
		translation_values_map translations;

		//Для работы со строками и трансляциями есть вспомогательный класс
		version_info_editor version(strings, translations);
		//Добавим трансляцию - default process language, UNICODE
		//Можно указать и конкретный язык и кодировку
		version.add_translation(version_info_editor::default_language_translation);
		//Строки будут устанавливаться для дефолтной кодировки (default_language_translation)
		//Если такой нет, то для первой найденной
		//Если вообще нет ни одной трансляции, то будет добавлена дефолтная (default_language_translation)
		//Таким образом, предыдущий вызов add_translation можно было бы опустить
		//И еще: необязательно устанавливать все доступные строки, как сделано ниже
		version.set_company_name(L"Kaimi.ru DX"); //Имя компании-производителя
		version.set_file_description(L"Generated file version info"); //Описание файла
		version.set_internal_name(L"Tralala.exe"); //Внутреннее имя файла
		version.set_legal_copyright(L"(C) DX Portable Executable Library"); //Копирайт
		version.set_original_filename(L"resource_editor.exe"); //Оригинальное имя файла
		version.set_product_name(L"PE Resource Editor Example"); //Имя продукта
		version.set_product_version(L"x.y.z"); //Версия продукта

		//Можно также добавить свою собственную строку: она будет храниться в информации о версии,
		//но Windows Explorer вряд ли ее отобразит в свойствах файла
		version.set_property(L"MyLittleProperty", L"Secret Value");

		//Установим информацию о версии
		resource_version_info_writer(res).set_version_info(file_info, strings, translations, 1033); //1033 - русский язык
		
		//Осталось переименовать старую секцию ресурсов
		//Она называется .rsrc
		//Переименование необходимо для того, чтобы Windows Explorer смог считать из новой секции иконку
		image.section_from_directory(pe_win::image_directory_entry_resource).set_name("oldres");

		//Пересоберем ресурсы
		//Они будет иметь больший размер, чем до нашего редактирования,
		//поэтому запишем их в новую секцию, чтобы все поместилось
		//(мы не можем расширять существующие секции, если только секция не в самом конце файла)
		section new_resources;
		new_resources.get_raw_data().resize(1); //Мы не можем добавлять пустые секции, поэтому пусть у нее будет начальный размер данных 1
		new_resources.set_name(".rsrc"); //Имя секции
		new_resources.readable(true); //Доступна на чтение
		section& attached_section = image.add_section(new_resources); //Добавим секцию и получим ссылку на добавленную секцию с просчитанными размерами
		
		//Теперь пересоберем ресурсы, расположив их в самом начале новой секции и поправив PE-заголовок, записав туда новые параметры директории ресурсы
		rebuild_resources(image, root, attached_section);
		
		//Создаем новый PE-файл
		std::string base_file_name(pe_filename);
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
