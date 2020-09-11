#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include <pe_bliss_resources.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как читать ресурсы PE-файла
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: resource_viewer.exe PE_FILE" << std::endl;
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

		//Проверим, есть ли ресурсы у файла
		if(!image.has_resources())
		{
			std::cout << "Image has no resources" << std::endl;
			return 0;
		}

		//Получаем корневую директорию ресурсов
		std::cout << "Reading PE resources..." << std::hex << std::showbase << std::endl << std::endl;
		const resource_directory root(get_resources(image));

		//Для облегчения работы с директориями и записями ресурсов созданы вспомогательные классы
		//Этот класс позволяет извлекать из PE-файлов любые ресурсы
		//и предоставляет высокоуровневые функции для извечения иконок, курсоров, картинкок, строковых таблиц
		//и таблиц сообщений, а также информации о версии
		pe_resource_viewer res(root);

		//Выведем типы ресурсов, которые присутствуют в PE-файле
		pe_resource_viewer::resource_type_list res_types(res.list_resource_types());
		for(pe_resource_viewer::resource_type_list::const_iterator it = res_types.begin(); it != res_types.end(); ++it)
			std::cout << "Present resource type: " << (*it) << std::endl;

		std::cout << std::endl;

		//Выведем иофнрмацию о версии, если она существует
		if(res.resource_exists(pe_resource_viewer::resource_version))
		{
			lang_string_values_map strings;
			translation_values_map translations;
			//Получаем список строк, переводов и базовую информацию о файле
			file_version_info file_info(resource_version_info_reader(res).get_version_info(strings, translations));

			//Выводить информацию будем в юникодный поток
			std::wstringstream version_info;
			//Выведем некоторую базовую информацию
			version_info << L"Version info: " << std::endl;
			version_info << L"File version: " << file_info.get_file_version_string<wchar_t>() << std::endl; //Строка версии файла
			version_info << L"Debug build: " << (file_info.is_debug() ? L"YES" : L"NO") << std::endl; //Отладочный ли билд
			version_info << std::endl;

			//Выведем строки для разных трансляций:
			for(lang_string_values_map::const_iterator it = strings.begin(); it != strings.end(); ++it)
			{
				version_info << L"Translation ID: " << (*it).first << std::endl;

				//Перечислим записи в таблице строк для текущей трансляции (перевода)
				const string_values_map& string_table = (*it).second;
				for(string_values_map::const_iterator str_it = string_table.begin(); str_it != string_table.end(); ++str_it)
					version_info << (*str_it).first << L": " << (*str_it).second << std::endl;

				version_info << std::endl;
			}
			
			//Выведем доступные переводы (трансляции):
			for(translation_values_map::const_iterator it = translations.begin(); it != translations.end(); ++it)
				version_info << L"Translation: language: " << (*it).first << ", codepage: " << (*it).second << std::endl;

			{
				//Создаем файл, в который запишем информацию о версии
				std::ofstream version_info_file("version_info.txt", std::ios::out | std::ios::trunc | std::ios::binary);
				if(!version_info_file)
				{
					std::cout << "Cannot create file version_info.txt" << std::endl;
					return -1;
				}

				std::wstring version_info_string(version_info.str());
				//Запишем буфер, чтобы не париться с локалями и записью юникода в файл
				version_info_file.write(reinterpret_cast<const char*>(version_info_string.data()), version_info_string.length() * sizeof(wchar_t));

				std::cout << "version_info.txt created" << std::endl << std::endl;
			}

			//Для облегчения чтения информации о версии есть специальный класс
			version_info_viewer version_viewer(strings, translations);
			std::wcout << L"Original filename: " << version_viewer.get_original_filename() << std::endl << std::endl;
		}

		{
			//Найдем, есть ли у приложения иконка
			//Для этого сначала узнаем все имена и идентификаторы групп иконок
			//Все ресурсы в целом организованы в таком виде (дерево):
			//тип ресурса
			//--> имя ресурса
			//----> язык рерурса
			//------> ресурс
			//----> язык ресурса
			//------> ресурс
			//----> ...
			//--> имя ресурса
			//--> ...
			//--> id ресурса
			//----> язык рерурса
			//------> ресурс
			//----> язык ресурса
			//------> ресурс
			//----> ...
			//--> id ресурса
			//--> ...
			//тип ресурса
			//...
			pe_resource_viewer::resource_id_list icon_id_list(res.list_resource_ids(pe_resource_viewer::resource_icon_group));
			pe_resource_viewer::resource_name_list icon_name_list(res.list_resource_names(pe_resource_viewer::resource_icon_group));
			std::string main_icon; //Данные иконки приложения
			//Сначала всегда располагаются именованные ресурсы, поэтому проверим, есть ли они
			if(!icon_name_list.empty())
			{
				//Получим самую первую иконку для самого первого языка (по индексу 0)
				//Если надо было бы перечислить языки для заданной иконки, можно было вызвать list_resource_languages
				//Если надо было бы получить иконку для конкретного языка, можно было вызвать get_icon_by_name (перегрузка с указанием языка)
				main_icon = resource_cursor_icon_reader(res).get_icon_by_name(icon_name_list[0]);
			}
			else if(!icon_id_list.empty()) //Если нет именованных групп иконок, но есть группы с ID
			{
				//Получим самую первую иконку для самого первого языка (по индексу 0)
				//Если надо было бы перечислить языки для заданной иконки, можно было вызвать list_resource_languages
				//Если надо было бы получить иконку для конкретного языка, можно было вызвать get_icon_by_id_lang
				main_icon = resource_cursor_icon_reader(res).get_icon_by_id(icon_id_list[0]);
			}

			//Если есть иконка...
			if(!main_icon.empty())
			{
				//Сохраним полученную иконку в файл
				std::ofstream app_icon("main_icon.ico", std::ios::out | std::ios::trunc | std::ios::binary);
				if(!app_icon)
				{
					std::cout << "Cannot create file main_icon.ico" << std::endl;
					return -1;
				}

				app_icon.write(main_icon.data(), main_icon.length());

				std::cout << "main_icon.ico created" << std::endl;
			}
		}

		{
			//Сдампим строковые таблицы
			//Перечислим идентификаторы существующих строковых таблиц
			pe_resource_viewer::resource_id_list strings_id_list(res.list_resource_ids(pe_resource_viewer::resource_string));

			//Дампить будем в юникодный поток
			std::wstringstream string_data;

			if(!strings_id_list.empty()) //Если у нас есть именованные строковые таблицы, сдампим их
			{
				//Все имена строковых таблиц
				for(pe_resource_viewer::resource_id_list::const_iterator it = strings_id_list.begin(); it != strings_id_list.end(); ++it)
				{
					string_data << L"String table [" << (*it) << L"]" << std::endl;

					//Перечислим языки таблицы
					pe_resource_viewer::resource_language_list langs(res.list_resource_languages(pe_resource_viewer::resource_string, *it));
					//Для каждого языка получим таблицу строк
					for(pe_resource_viewer::resource_language_list::const_iterator lang_it = langs.begin(); lang_it != langs.end(); ++lang_it)
					{
						string_data << L" -> Language = " << *lang_it << std::endl; //Запишем язык
						//Таблица строк
						resource_string_list strings(resource_string_table_reader(res).get_string_table_by_id_lang(*lang_it, *it));

						//Наконец, запишем все строки в поток
						for(resource_string_list::const_iterator str_it = strings.begin(); str_it != strings.end(); ++str_it)
							string_data << L" --> #" << (*str_it).first << L": " << (*str_it).second << std::endl; //ID строки: ее значение
					}

					string_data << std::endl;
				}
				
				//Запишем полученные строки в файл
				std::ofstream strings_file("strings.txt", std::ios::out | std::ios::trunc | std::ios::binary);
				if(!strings_file)
				{
					std::cout << "Cannot create file strings.txt" << std::endl;
					return -1;
				}

				std::wstring strings_str(string_data.str());
				//Запишем буфер, чтобы не париться с локалями и записью юникода в файл
				strings_file.write(reinterpret_cast<const char*>(strings_str.data()), strings_str.length() * sizeof(wchar_t));

				std::cout << "strings.txt created" << std::endl;
			}
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
