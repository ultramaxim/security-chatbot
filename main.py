import telebot
from telebot import apihelper
from telebot import types
import requests, json, re, os


token = os.getenv('token')

bot = telebot.TeleBot(token)
#apihelper.proxy = proxy

chat_id = {}

@bot.message_handler(commands=['start'])
def start(message):
    chat_id[message.chat.id]={}
    keyboard = types.InlineKeyboardMarkup()
    npm_button = types.InlineKeyboardButton(text='пакеты разработки JavaScript', callback_data='npm')
    maven_button = types.InlineKeyboardButton(text='пакеты разработки JAVA', callback_data='maven')
    pypi_button = types.InlineKeyboardButton(text='пакеты разработки Python', callback_data='pypi')
    go_button = types.InlineKeyboardButton(text='пакеты разработки GO lang', callback_data='go')
    keyboard.add(npm_button)
    keyboard.add(maven_button)
    keyboard.add(pypi_button)
    keyboard.add(go_button)

    bot.send_message(message.chat.id, 'Выбери язык разработки', reply_markup=keyboard)



@bot.message_handler(content_types=['text'])
def show_message(message):
    print("введен текст: "+ str(message.text)+" из чата "+str(message.chat.id))
    bot.send_message(message.chat.id, "то, что вы ввели, не привязано ни к какому действию, нужно нажать на кноки выше и в ответном сообщении указать верную информацию")
 

# Inline keyboard
@bot.callback_query_handler(func=lambda call: True)
def callback_inline(call):
    global chat_id
    if call.data == 'npm' or call.data == 'maven' or call.data == 'pypi' or call.data == 'go':
        markup = types.ReplyKeyboardMarkup()
        msg = bot.reply_to(call.message, 'Введи название пакета разработки '+call.data)
        if call.data == 'maven':
            bot.send_message(call.message.chat.id, "Для JAVA-пакетов используй следующий формат - <group ID>:<artifact ID>, например, org.apache.logging.log4j:log4j-core")
        if call.data == 'go':
            bot.send_message(call.message.chat.id, "Для go-пакетов используй полный путь до пакета , например, github.com/botwayorg/git или go.etcd.io/etcd/client/pkg/v3")

        print("выбран пакет: "+ call.data+" из чата "+str(call.message.chat.id))
        bot.edit_message_reply_markup(call.message.chat.id,call.message.id, "",reply_markup=[])

        chat_id[call.message.chat.id]={}
        chat_id[call.message.chat.id]={"type_packet":str(call.data)}
        bot.register_next_step_handler(msg, send_package_name)

    if call.data == "know_version":
        msg2 = bot.reply_to(call.message, 'укажите версию проверяемого пакета')
        print("Пользователь выбран указание конкретной версии проверяемого пакета: "+ str(call.message.text)+" из чата "+str(call.message.chat.id))
        bot.register_next_step_handler(msg2, send_package_version)



    if call.data == "dont_know_version":
        print("Пользователь выбрал показать все версии, запрос из чата "+str(call.message.chat.id))
        bot.send_message(call.message.chat.id, "все версии пакета "+chat_id[call.message.chat.id]['packet']+":")
        bot.send_message(call.message.chat.id, show_versions(call.message))

    if call.data == "without_dos":
        print("Пользователь выбрал покажи уязвимости без DOS , запрос из чата "+str(call.message.chat.id))
        bot.send_message(call.message.chat.id, show_vulns(get_full_packet_vulns(chat_id[call.message.chat.id]['type_packet'],chat_id[call.message.chat.id]['packet'],chat_id[call.message.chat.id]['version_of_packet'],True)))


    if call.data == "dont_know_version_show_vulns":
        bot.send_message(call.message.chat.id, "все версии пакета c указанием наличия высоких или критических уязвимостей "+chat_id[call.message.chat.id]['packet']+":")


        bot.send_message(call.message.chat.id, show_versions_with_vulns(call.message))


    if call.data == "got_clean_version":
        got_clean_version(call.message)

def show_versions_with_vulns(message):
    global chat_id
    if 'version_with_vulns_task' in chat_id[message.chat.id]:
        if chat_id[message.chat.id]['version_with_vulns_task']:
            bot.send_message(message.chat.id, "Уже запущена задача анализа всех версий пакета, она довольно трудоёмкая")
            bot.send_message(message.chat.id, "поэтому дождись окончания работы предыдущего таска и попробуй снова")
    else:
        chat_id[message.chat.id]['version_with_vulns_task'] = True
        versions = show_versions(message).split('\n')
        versions.pop()
        result = ""
        result_dos_high = ""
        result_dos_critical = ""
        print(versions)
        for ver in versions:
            if ver == " ":
                print("pass")
                pass
            print(ver)
            temp_result= "с DOS: "
            result_dos = show_vulns(get_full_packet_vulns(chat_id[message.chat.id]['type_packet'],chat_id[message.chat.id]['packet'],ver,False))
            policy_dos_high = re.search(r"уровень критичности: high", result_dos, re.IGNORECASE)
            if policy_dos_high:
                result_dos_high = "🟠 "
            policy_dos_critical = re.search(r"уровень критичности: critical", result_dos, re.IGNORECASE)
            if policy_dos_critical:
                result_dos_critical ="🔴 "

            temp_result+=result_dos_critical+result_dos_high
            if not re.search(r"(🟠|🔴)", result, re.IGNORECASE):
                temp_result+="🟢 "

            temp_result2= "без DOS: "

            result_no_dos = show_vulns(get_full_packet_vulns(chat_id[message.chat.id]['type_packet'],chat_id[message.chat.id]['packet'],ver,True))
            result_no_dos_critical =""
            result_no_dos_high = ""

            if re.search(r"уровень критичности: high", result_no_dos, re.IGNORECASE):
                result_no_dos_high = "🟠 "
            if re.search(r"уровень критичности: critical", result_no_dos, re.IGNORECASE):
                result_no_dos_critical ="🔴 "

            temp_result2+=result_no_dos_critical+result_no_dos_high
            if not re.search(r"(🟠|🔴)", result, re.IGNORECASE):
                temp_result2+="🟢 "

            result+=ver+" "+temp_result+temp_result2+"\n"
        chat_id[message.chat.id]['version_with_vulns_task'] = False
        return result

def got_clean_version(message):
    global chat_id
    if 'clean_version_task' in chat_id[message.chat.id]:
        if chat_id[message.chat.id]['clean_version_task']:
            bot.send_message(message.chat.id, "Уже запущена задача поиска подходящей версии, она довольно трудоёмкая")
            bot.send_message(message.chat.id, "поэтому дождись окончания работы предыдущего таска и попробуй снова")
    else:
        chat_id[message.chat.id]['clean_version_task'] = True
        count = 0
        my_version_number = 0
        best_version_dos = ""
        best_version_no_dos = ""
        for i in chat_id[message.chat.id]['versions']:
            if i['versionKey']['version'] == chat_id[message.chat.id]['version_of_packet']:
                my_version_number = count
            count +=1
        
        if my_version_number == count:
            bot.send_message(message.chat.id, "У вас самая последняя версия пакета")
        
        else:
            for i in range(my_version_number+1,count):
                result_dos = show_vulns(get_full_packet_vulns(chat_id[message.chat.id]['type_packet'],chat_id[message.chat.id]['packet'],str(chat_id[message.chat.id]['versions'][i]['versionKey']['version']),False))
                policy_dos = re.search(r"уровень критичности: (high|critical)", result_dos, re.IGNORECASE)
                    
                if not policy_dos:
                    if best_version_dos == "":
                        best_version_dos = str(chat_id[message.chat.id]['versions'][i]['versionKey']['version'])
            
                result_without_dos = show_vulns(get_full_packet_vulns(chat_id[message.chat.id]['type_packet'],chat_id[message.chat.id]['packet'],str(chat_id[message.chat.id]['versions'][i]['versionKey']['version']),True))    
                policy_without_dos = re.search(r"уровень критичности: (high|critical)", result_without_dos, re.IGNORECASE)
                
                if not policy_without_dos:
                    if best_version_no_dos == "":
                        best_version_no_dos = str(chat_id[message.chat.id]['versions'][i]['versionKey']['version'])

            bot.send_message(message.chat.id, "Анализ будет произведен для версии строго больше ранее указанной вами")
            
            if (best_version_dos == ""):
                bot.send_message(message.chat.id, "К сожалению, не существует версии без высоких и критических уязвимостей (с уязвимостями, приводящим к DOS)")
            else:
                bot.send_message(message.chat.id, "Подходящяя версия пакета "+str(chat_id[message.chat.id]['packet'])+" без высоких и критических уязвимостей (с уязвимостями, приводящим к DOS) - "+best_version_dos)
            

            if (best_version_no_dos == ""):
                bot.send_message(message.chat.id, "К сожалению, не существует версии без высоких и критических уязвимостей (не учитываются уязвимости, приводящие к DOS)")
            else:
                bot.send_message(message.chat.id, "Подходящяя версия пакета "+str(chat_id[message.chat.id]['packet'])+" без высоких и критических уязвимостей (не учитываются уязвимости, приводящие к DOS) - "+best_version_no_dos)
        chat_id[message.chat.id]['clean_version_task'] = False

def show_versions(message):
    versions = ""
    for i in chat_id[message.chat.id]['versions']:
        versions += i['versionKey']['version']+"\n"
    return versions

def send_package_name(message):
    if message.text == "/start":
        #return False
        start(message)
        return False
    global chat_id
    if message.chat.id in chat_id:
        url = 'https://api.deps.dev/v3alpha/systems/'+chat_id[message.chat.id]['type_packet']+'/packages/'+str(message.text).lower()

        print("попытка определить наличие пакета в репозитории следующей командой "+url+", запрос из чата "+str(message.chat.id))

        resp = requests.get(url)
        #print(resp.text)
        if(resp.status_code == 404):
            bot.send_message(message.chat.id, "Пакет "+str(message.text).lower()+" отсутствует в репозитории "+chat_id[message.chat.id]['type_packet'])
            print("Пакет "+str(message.text).lower()+" отсутствует в репозитории "+chat_id[message.chat.id]['type_packet']+", запрос из чата "+str(message.chat.id))
        else:
            resp_parse = json.loads(resp.text)
            tmp_dict = {"packet":str(message.text).lower(),"versions":resp_parse['versions']}
            chat_id[message.chat.id].update(tmp_dict)
            bot.send_message(message.chat.id, 'Пакет найден в репозитории')

            print("Пакет "+str(message.text).lower()+"найден в репозитории , запрос из чата "+str(message.chat.id))

            keyboard = types.InlineKeyboardMarkup()
            known_button = types.InlineKeyboardButton(text='Знаю версию пакета', callback_data='know_version')
            stupid_button = types.InlineKeyboardButton(text='Покажи все версии', callback_data='dont_know_version')
            #not_so_stupid_button = types.InlineKeyboardButton(text='Не знаю версию пакета, подскажите, какие есть c подкрашиванием, уявзима ли версия', callback_data='dont_know_version_show_vulns')
            keyboard.add(known_button)
            keyboard.add(stupid_button)
            #keyboard.add(not_so_stupid_button)
            bot.send_message(message.chat.id, 'Теперь укажите версию проверяемого пакета',reply_markup=keyboard)
       
def send_package_version(message):
    if message.text == "/start":
        #return False
        start(message)
        return False
    
    if message.chat.id in chat_id:
        if 'packet' in chat_id[message.chat.id]:
            url = 'https://api.deps.dev/v3alpha/systems/'+chat_id[message.chat.id]['type_packet']+'/packages/'+chat_id[message.chat.id]['packet']+'/versions/'+str(message.text)
    
            resp = requests.get(url)
    
            if (resp.status_code == 404):
                bot.send_message(message.chat.id, "Версия "+str(message.text)+" пакета "+ str(chat_id[message.chat.id]['packet'])+" отсутствует в репозитории "+str(chat_id[message.chat.id]['type_packet'])) 
                print("Версия "+str(message.text)+" пакета "+ str(chat_id[message.chat.id]['packet'])+" отсутствует в репозитории "+str(chat_id[message.chat.id]['type_packet'])+", запрос из чата "+str(message.chat.id))
                return False
            else:
                tmp_dict = {"version_of_packet":str(message.text).lower()}
                chat_id[message.chat.id].update(tmp_dict)
                result = show_vulns(get_full_packet_vulns(chat_id[message.chat.id]['type_packet'],chat_id[message.chat.id]['packet'],str(message.text),False)) 
                bot.send_message(message.chat.id, result)
        
        
                keyboard = types.InlineKeyboardMarkup()
                without_dos = types.InlineKeyboardButton(text='не учитывать DoS', callback_data='without_dos')
                got_clean_version = types.InlineKeyboardButton(text='Подобрать версию без уязвимостей', callback_data='got_clean_version')
                keyboard.add(without_dos)
                keyboard.add(got_clean_version)
                bot.send_message(message.chat.id, 'Что делаем дальше?',reply_markup=keyboard)

                return result

def show_vulns(dict):
    direct_flag = True
    indirect_flag = True
    exist_direct = False
    exist_indirect = False
    direct_has_vuln = False
    indirect_has_vuln = False
    self_has_vuln = False

    self_exist_vuln = False
    direct_exist_vuln = False
    indirect_exist_vuln = False

    #print(dict)

    for i in dict:
        if dict[i]['relation']=="DIRECT":
            exist_direct = True
        if dict[i]['relation'] == "INDIRECT":
            exist_indirect = True
    result_string = ""
    for i in dict:
        flag_policy = False            
        
        if dict[i]['vulns'] != "no vuln's":
            if dict[i]['relation'] == "SELF": 
                
                result_string+='Уязвимости в самом пакете:\n\n'
            #bot.send_message(message.from_user.id, 'Уязвимости в самом пакете:', reply_markup=markup)

                self_exist_vuln = True
                for j in dict[i]['vulns']:
                    vulns = dict[i]['vulns'][j]
                    
                    if str(vulns['severity'])=="high":
                        self_has_vuln = True
                        result_string+="🟠 "+dict[i]['name']+' - '+dict[i]['version'] +" CVSS скоринг: "+str(vulns['CVSS скоринг'])+", CVE: "+str(vulns['CVE'])+", Описание: "+str(vulns['Описание'])+", уровень критичности: "+str(vulns['severity'])+"\n"
                    elif str(vulns['severity'])=="critical":
                        self_has_vuln = True
                        result_string+="🔴 "+dict[i]['name']+' - '+dict[i]['version'] +" CVSS скоринг: "+str(vulns['CVSS скоринг'])+", CVE: "+str(vulns['CVE'])+", Описание: "+str(vulns['Описание'])+", уровень критичности: "+str(vulns['severity'])+"\n"
                         
            if dict[i]['relation'] == "DIRECT":
                #print(dict[i]['name'])
                if (exist_direct and direct_flag):
                    result_string+="\nУязвимости в прямых зависимостях:\n\n"
                    #bot.send_message(message.from_user.id, 'Уязвимости в прямых зависимостях:', reply_markup=markup)
                direct_flag = False
            
                for j in dict[i]['vulns']:
                    vulns = dict[i]['vulns'][j]
                    
                    #if str(vulns['severity'])=="high" or str(vulns['severity'])=="critical":       
                    if str(vulns['severity'])=="high": 
                        direct_has_vuln = True
                        result_string+="🟠 Пакет "+dict[i]['name']+' - '+dict[i]['version'] +" CVSS скоринг: "+str(vulns['CVSS скоринг'])+", CVE: "+str(vulns['CVE'])+", Описание: "+str(vulns['Описание'])+", уровень критичности: "+str(vulns['severity'])+"\n"
                        #bot.send_message(message.from_user.id, "Пакет "+dict[i]['name']+' - '+dict[i]['version'] +" CVSS скоринг: "+str(vulns['CVSS скоринг'])+", CVE: "+str(vulns['CVE'])+", Описание: "+str(vulns['Описание'])+", уровень критичности: "+str(vulns['severity']))
                    if str(vulns['severity'])=="critical": 
                        direct_has_vuln = True
                        result_string+="🔴 Пакет "+dict[i]['name']+' - '+dict[i]['version'] +" CVSS скоринг: "+str(vulns['CVSS скоринг'])+", CVE: "+str(vulns['CVE'])+", Описание: "+str(vulns['Описание'])+", уровень критичности: "+str(vulns['severity'])+"\n"
                        #bot.send_message(message.from_user.id, "Пакет "+dict[i]['name']+' - '+dict[i]['version'] +" CVSS скоринг: "+str(vulns['CVSS скоринг'])+", CVE: "+str(vulns['CVE'])+", Описание: "+str(vulns['Описание'])+", уровень критичности: "+str(vulns['severity']))
            
            
            if dict[i]['relation'] == "INDIRECT":
                if (exist_indirect and indirect_flag):
                    result_string+='\nУязвимости в транзитивных зависимостях:\n\n'
                    #bot.send_message(message.from_user.id, 'Уязвимости в транзитивных зависимостях:', reply_markup=markup)
                indirect_flag = False
            
                for j in dict[i]['vulns']:
                    vulns = dict[i]['vulns'][j]
                    
                    if str(vulns['severity'])=="high":       
                        indirect_has_vuln = True
                        result_string+="🟠 Пакет "+dict[i]['name']+' - '+dict[i]['version']+" CVSS скоринг: "+str(vulns['CVSS скоринг'])+", CVE: "+str(vulns['CVE'])+", Описание: "+str(vulns['Описание'])+", уровень критичности: "+str(vulns['severity'])+"\n"
                        #bot.send_message(message.from_user.id, "Пакет "+dict[i]['name']+' - '+dict[i]['version']+" CVSS скоринг: "+str(vulns['CVSS скоринг'])+", CVE: "+str(vulns['CVE'])+", Описание: "+str(vulns['Описание'])+", уровень критичности: "+str(vulns['severity']))
                    if str(vulns['severity'])=="critical":       
                        indirect_has_vuln = True
                        result_string+="🔴 Пакет "+dict[i]['name']+' - '+dict[i]['version']+" CVSS скоринг: "+str(vulns['CVSS скоринг'])+", CVE: "+str(vulns['CVE'])+", Описание: "+str(vulns['Описание'])+", уровень критичности: "+str(vulns['severity'])+"\n"
                        #bot.send_message(message.from_user.id, "Пакет "+dict[i]['name']+' - '+dict[i]['version']+" CVSS скоринг: "+str(vulns['CVSS скоринг'])+", CVE: "+str(vulns['CVE'])+", Описание: "+str(vulns['Описание'])+", уровень критичности: "+str(vulns['severity']))
        

        
        else:
                if dict[i]['relation'] == "SELF":
                    if not self_exist_vuln:
                        result_string+='🟡 В самом пакете '+dict[i]['name']+' - '+dict[i]['version'] +' нет высоких и критических уязвимостей\n'
                        #bot.send_message(message.from_user.id, '🟢 В самом пакете '+dict[i]['name']+' - '+dict[i]['version'] +' нет высоких и критических уязвимостей',reply_markup=markup)
                    else: 
                        result_string+='🟢 В самом пакете '+dict[i]['name']+' - '+dict[i]['version'] +' вообще нет уязвимостей\n'
                        #bot.send_message(message.from_user.id, '🟢 В самом пакете '+dict[i]['name']+' - '+dict[i]['version'] +' вообще нет уязвимостей',reply_markup=markup)

                if dict[i]['relation'] == "DIRECT":
                    if (exist_direct and direct_flag):
                        result_string+='\nУязвимости в прямых зависимостях:\n\n'
                        #bot.send_message(message.from_user.id, 'Уязвимости в прямых зависимостях:', reply_markup=markup)
                        direct_flag = False
                    if not direct_has_vuln:
                        result_string+='🟡 Пакет '+dict[i]['name']+' - '+dict[i]['version'] +' не имеет высоких и критических уязвимостей\n'
                        #bot.send_message(message.from_user.id, '🟢 Пакет '+dict[i]['name']+' - '+dict[i]['version'] +' не имеет высоких и критических уязвимостей',reply_markup=markup)
               
                if dict[i]['relation'] == "INDIRECT" :
                    
                    if (exist_indirect and indirect_flag):
                        result_string+='\nУязвимости в транзитивных зависимостях:\n\n'
                        #bot.send_message(message.from_user.id, 'Уязвимости в транзитивных зависимостях:', reply_markup=markup)
                        indirect_flag = False 

                    if direct_has_vuln:
                        result_string+='🟢 Пакет '+dict[i]['name']+' - '+dict[i]['version'] +' вообще не имеет уязвимостей\n'
                        #bot.send_message(message.from_user.id, '🟢 Пакет '+dict[i]['name']+' - '+dict[i]['version'] +' вообще не имеет уязвимостей',reply_markup=markup)
    #print(result_string)
    return result_string

def get_full_packet_vulns(packet_type, packet, packet_version,dos):
    result = {}
    deps = get_depencies(packet_type, packet, packet_version)
    for i in deps:
        vulns = get_self_packet_vulns(deps[i]['type'],deps[i]['name'],deps[i]['version'],dos)
        result[i]={"name":deps[i]['name'],"version":deps[i]['version'],"relation":deps[i]['relation'],"vulns":vulns}
    sorted_result = sort_vulns(result)
    #print(sorted_result)
    return sorted_result



def get_depencies(packet_type, packet, packet_version):
    dict = {}
    url = 'https://api.deps.dev/v3alpha/systems/'+packet_type+'/packages/'+packet+'/versions/'+packet_version+':dependencies'
    resp = requests.get(url)
    if resp.status_code == 200:
        resp_parse = json.loads(resp.text)
        count = 0
        for i in resp_parse['nodes']:
            dict[count]={"type":packet_type,"name":i['versionKey']['name'],"version":i['versionKey']['version'],"relation":i['relation']}
            count+=1
        return dict
    else:
        return False



def get_advisories(dict):
    if dict['advisoryKeys']:
        advisories = []
        for i in dict['advisoryKeys']:
            url = 'https://api.deps.dev/v3alpha/advisories/'+i['id']
            resp = requests.get(url)
            
            if(resp.status_code == 200):
                resp_parse = json.loads(resp.text)
                advisories.append(resp_parse)
        return advisories
    else:
        return "no vuln's"


def sort_vulns(dict):
    count =0
    return_dict = {}
    for i in dict:
        if dict[i]['relation'] == "SELF":
            return_dict[i]= dict[i]
            count+=1        
    for i in dict:
        if dict[i]['relation'] == "DIRECT":
            return_dict[i]= dict[i]
            count+=1
    for i in dict:
        if dict[i]['relation'] == "INDIRECT":
            return_dict[i]= dict[i]
            count+=1
    return return_dict


def get_self_packet_vulns(packet_type, packet, packet_version, dos):
    url = 'https://api.deps.dev/v3alpha/systems/'+packet_type+'/packages/'+packet+'/versions/'+packet_version
    resp = requests.get(url)

    if resp.status_code == 200:
        resp_parse = json.loads(resp.text)
        vulns_in_packet = get_advisories(resp_parse)
        if vulns_in_packet == "no vuln's":
            return "no vuln's"
        else:
            count = 0
            dict = {}
            #print(vulns_in_packet)
            for i in vulns_in_packet:
                #print(i)
                #if str(i['cvss3score']) == 0:
                #     dict[count]={"CVSS скоринг: "+str(i['cvss2Score'])+", CVE: "+str(i['aliases'])+", Описание: "+str(i['title'])}
                # else:
                x = re.search(r"(DoS|denial of service)", str(i['title']), re.IGNORECASE)
                str4dict = {}
                if x:
                    #dict[count]={"CVSS скоринг":str(i['cvss3Score']),"CVE":str(i['aliases']),"Описание":str(i['title']),"dos":"yes"}
                    if not dos:
                        str4dict = {"CVSS скоринг":str(i['cvss3Score']),"CVE":str(i['aliases']),"Описание":str(i['title']),"dos":"yes"}
                else:
                    str4dict={"CVSS скоринг":str(i['cvss3Score']),"CVE":str(i['aliases']),"Описание":str(i['title']),"dos":"no"}
                score = float(i['cvss3Score'])
                if x and dos:
                    pass
                else:
                    if score >= 7.0 and score < 8.5:
                        str4dict.update({'severity':'high'})
                    elif score >= 8.5:
                        str4dict.update({'severity':'critical'})
                    elif score >= 5.5 and score < 7.0:
                        str4dict.update({'severity':'medium'})
                    else:
                        str4dict.update({'severity':'low'})
                    dict[count]=str4dict            

                count+=1
            #print(dict)
            return dict


bot.polling(none_stop=True, interval=0) 
