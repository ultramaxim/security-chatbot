import telebot
from telebot import types
import requests,json,re

bot = telebot.TeleBot('')

chat_id = {}
markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
@bot.message_handler(commands=['start'])
def start(message):

   
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    btn1 = types.KeyboardButton("Проверить уязвимости в библиотеке разработки (python, java, go, npm)")
    markup.add(btn1)
    bot.send_message(message.from_user.id, "👋 Привет! Пока здесь ты можешь проверить библиотеки разработки на уязвимости, дальше функционал будет расширяться", reply_markup=markup)


@bot.message_handler(commands=['check_package'])
def check_package(message):
      
    if message.text == 'Проверить уязвимости в библиотеке разработки (python, java, go, npm)':
        
        markup = types.ReplyKeyboardMarkup(resize_keyboard=True) #создание новых кнопок
        btn1 = types.KeyboardButton('npm')
        btn2 = types.KeyboardButton('maven')
        btn3 = types.KeyboardButton('pypi')
        btn4 = types.KeyboardButton('go')
        markup.add(btn1, btn2, btn3,btn4)
        bot.send_message(message.from_user.id, 'выбери язык разработки', reply_markup=markup) #ответ бота
        if message.chat.id in chat_id: del chat_id[message.chat.id]

@bot.message_handler(content_types=['text'])
def get_text_messages(message):

  
    global chat_id, markup    
    if message.text == 'Проверить уязвимости в библиотеке разработки (python, java, go, npm)':
        
        markup = types.ReplyKeyboardMarkup(resize_keyboard=True) #создание новых кнопок
        btn1 = types.KeyboardButton('npm')
        btn2 = types.KeyboardButton('maven')
        btn3 = types.KeyboardButton('pypi')
        btn4 = types.KeyboardButton('go')
        markup.add(btn1, btn2, btn3,btn4)
        bot.send_message(message.from_user.id, 'выбери язык разработки', reply_markup=markup) #ответ бота
        if message.chat.id in chat_id: del chat_id[message.chat.id]
    elif message.chat.id in chat_id:
        #print("in elif in 33 line")
        #print(chat_id)
        #print("going to run get_version")
        
        if 'packet' in chat_id[message.chat.id]:
            if 'packet_version' in chat_id[message.chat.id]:
                check_version(message)
                
        else:
            get_version(message)
    elif message.text == 'npm' or message.text == 'pypi' or message.text == 'maven' or message.text == 'go':
        if message.chat.id in chat_id: del chat_id[message.chat.id]
        
        markup = types.ForceReply(selective=False)
        
        chat_id[message.chat.id] = {"type_packet":message.text}
        #print(chat_id[message.chat.id]['type_packet'])
        bot.send_message(message.from_user.id, 'Введите название пакета', reply_markup=markup)
  
    else:
        markup = types.ForceReply(selective=False)
        bot.send_message(message.from_user.id, 'Что-то пошло не так, попробуй снова или выбери другой пакет',reply_markup=markup)


def get_version(message):
    global chat_id, markup
    url = 'https://api.deps.dev/v3alpha/systems/'+str(chat_id[message.chat.id]['type_packet'])+'/packages/'+str(message.text).lower()
    #print("func get_version, try to curl "+url)
    resp = requests.get(url)
    #print(resp.text)
    if(resp.status_code == 404):
        bot.send_message(message.from_user.id, "Пакет "+str(message.text).lower()+" отсутствует в репозитории "+str(chat_id[message.chat.id]['type_packet']), reply_markup=markup)   
    else:
        tmp_dict = {"packet":str(message.text).lower()}
        chat_id[message.chat.id].update(tmp_dict)
        bot.send_message(message.from_user.id, 'Пакет найден в репозитории', reply_markup=markup)
        bot.send_message(message.from_user.id, 'Теперь укажите версию проверяемого пакета', reply_markup=markup)
        tmp_dict = {"packet_version":"yes"}
        chat_id[message.chat.id].update(tmp_dict)

def check_version(message):
    url = 'https://api.deps.dev/v3alpha/systems/'+str(chat_id[message.chat.id]['type_packet'])+'/packages/'+str(chat_id[message.chat.id]['packet'])+'/versions/'+message.text
    #print("func check_version, try to curl "+url)
    resp = requests.get(url)
    #print(resp.text)

    if (resp.status_code == 404):
        bot.send_message(message.from_user.id, "Версия "+message.text+" пакета "+ str(chat_id[message.chat.id]['packet'])+" отсутствует в репозитории "+str(chat_id[message.chat.id]['type_packet']), reply_markup=markup) 
    else:

        #resp_parse = json.loads(resp.text)
        #adv = get_advisories(resp_parse)
        #deps = get_depencies(str(chat_id[message.chat.id]['type_packet']),str(chat_id[message.chat.id]['packet']),message.text)
        #for i in deps:
        show_vulns(get_full_packet_vulns(str(chat_id[message.chat.id]['type_packet']),str(chat_id[message.chat.id]['packet']),message.text),message)   
        
        #if adv == "no vuln's":
        #    bot.send_message(message.from_user.id, 'В указанном пакете нет уязвимостей!',reply_markup=markup)
        #else:
        #    bot.send_message(message.from_user.id, 'В указанном пакете есть уязвимости...')
        #    for i in adv:
        #        bot.send_message(message.from_user.id, "CVSS скоринг: "+str(i['cvss3Score'])+", CVE: "+str(i['aliases'])+", Описание: "+str(i['title']))
        #    markup2 = types.ReplyKeyboardMarkup(resize_keyboard=False)
        #    btn1 = types.KeyboardButton('DoS-не критичен')
        #    btn2 = types.KeyboardButton('Подобрать версию без уязвимостей (DoS не критичен)')
        #    btn3 = types.KeyboardButton('Подобрать пакет без уязвимостей (DoS критичен)')
        #    markup2.add(btn1, btn2, btn3)
        #    bot.send_message(message.from_user.id, 'обрати внимание на дополнительные опции по анализу', reply_markup=markup2)
        #    print(get_depencies(str(chat_id[message.chat.id]['type_packet']),str(chat_id[message.chat.id]['packet']),message.text))


def show_vulns(dict, message):
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

    for i in dict:
        if dict[i]['relation']=="DIRECT":
            exist_direct = True
        if dict[i]['relation'] == "INDIRECT":
            exist_indirect = True
    #print (dict)
    for i in dict:
        flag_policy = False            
        
        if dict[i]['vulns'] != "no vuln's":
            if dict[i]['relation'] == "SELF": 
                bot.send_message(message.from_user.id, 'Уязвимости в самом пакете:', reply_markup=markup)

                self_exist_vuln = True
                for j in dict[i]['vulns']:
                    vulns = dict[i]['vulns'][j]
                    
                    if str(vulns['severity'])=="high" or str(vulns['severity'])=="critical":       
                        print(vulns)
                        self_has_vuln = True
                        bot.send_message(message.from_user.id, dict[i]['name']+' - '+dict[i]['version'] +" CVSS скоринг: "+str(vulns['CVSS скоринг'])+", CVE: "+str(vulns['CVE'])+", Описание: "+str(vulns['Описание'])+", уровень критичности: "+str(vulns['severity']))
        
            if dict[i]['relation'] == "DIRECT":
                if (exist_direct and direct_flag):
                    bot.send_message(message.from_user.id, 'Уязвимости в прямых зависимостях:', reply_markup=markup)
                direct_flag = False
            
                for j in dict[i]['vulns']:
                    vulns = dict[i]['vulns'][j]
                    
                    if str(vulns['severity'])=="high" or str(vulns['severity'])=="critical":       
                        direct_has_vuln = True
                        bot.send_message(message.from_user.id, dict[i]['name']+' - '+dict[i]['version'] +" CVSS скоринг: "+str(vulns['CVSS скоринг'])+", CVE: "+str(vulns['CVE'])+", Описание: "+str(vulns['Описание'])+", уровень критичности: "+str(vulns['severity']))
        
            if dict[i]['relation'] == "INDIRECT":
                if (exist_indirect and indirect_flag):
                    bot.send_message(message.from_user.id, 'Уязвимости в транзитивных зависимостях:', reply_markup=markup)
                indirect_flag = False
            
                for j in dict[i]['vulns']:
                    vulns = dict[i]['vulns'][j]
                    
                    if str(vulns['severity'])=="high" or str(vulns['severity'])=="critical":       
                        indirect_has_vuln = True
                        bot.send_message(message.from_user.id, dict[i]['name']+' - '+dict[i]['version']+" CVSS скоринг: "+str(vulns['CVSS скоринг'])+", CVE: "+str(vulns['CVE'])+", Описание: "+str(vulns['Описание'])+", уровень критичности: "+str(vulns['severity']))
        

        
        else:
                if dict[i]['relation'] == "SELF":
                    if not self_exist_vuln:
                        bot.send_message(message.from_user.id, 'В самом пакете '+dict[i]['name']+' - '+dict[i]['version'] +' нет высоких и критических уязвимостей',reply_markup=markup)
                    else: 
                        bot.send_message(message.from_user.id, 'В самом пакете '+dict[i]['name']+' - '+dict[i]['version'] +' вообще нет уязвимостей',reply_markup=markup)

                #if dict[i]['relation'] == "DIRECT" or dict[i]['relation'] == "INDIRECT" :
                #    if not direct_has_vuln:
                #        bot.send_message(message.from_user.id, 'Пакет '+dict[i]['name']+' - '+dict[i]['version'] +' не имеет высоких и критических уязвимостей',reply_markup=markup)
                #    else:
                #        bot.send_message(message.from_user.id, 'Пакет '+dict[i]['name']+' - '+dict[i]['version'] +' вообще не имеет уязвимостей',reply_markup=markup)
        
        
        

            

        

    
def get_full_packet_vulns(packet_type, packet, packet_version):
    result = {}
    deps = get_depencies(packet_type, packet, packet_version)
    for i in deps:
        vulns = get_self_packet_vulns(deps[i]['type'],deps[i]['name'],deps[i]['version'])
        result[i]={"name":deps[i]['name'],"version":deps[i]['version'],"relation":deps[i]['relation'],"vulns":vulns}
    sorted_result = sort_vulns(result)
    #print(sorted_result)
    return sorted_result

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


def get_self_packet_vulns(packet_type, packet, packet_version):
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
                    str4dict = {"CVSS скоринг":str(i['cvss3Score']),"CVE":str(i['aliases']),"Описание":str(i['title']),"dos":"yes"}
                else:
                    str4dict={"CVSS скоринг":str(i['cvss3Score']),"CVE":str(i['aliases']),"Описание":str(i['title']),"dos":"no"}
                score = float(i['cvss3Score'])
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



bot.polling(none_stop=True, interval=0) 
