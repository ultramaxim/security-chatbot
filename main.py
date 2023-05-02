import telebot
from telebot import types
import requests,json

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
        print("in elif in 33 line")
        print(chat_id)
        print("going to run get_version")
        
        if 'packet' in chat_id[message.chat.id]:
            if 'packet_version' in chat_id[message.chat.id]:
                check_version(message)
                
        else:
            get_version(message)
    elif message.text == 'npm' or message.text == 'pypi' or message.text == 'maven' or message.text == 'go':
        if message.chat.id in chat_id: del chat_id[message.chat.id]
        
        markup = types.ForceReply(selective=False)
        
        chat_id[message.chat.id] = {"type_packet":message.text}
        print(chat_id[message.chat.id]['type_packet'])
        bot.send_message(message.from_user.id, 'Введите название пакета', reply_markup=markup)
  
    else:
        markup = types.ForceReply(selective=False)
        bot.send_message(message.from_user.id, 'Что-то пошло не так, попробуй снова или выбери другой пакет',reply_markup=markup)


def get_version(message):
    global chat_id, markup
    url = 'https://api.deps.dev/v3alpha/systems/'+str(chat_id[message.chat.id]['type_packet'])+'/packages/'+str(message.text).lower()
    print("func get_version, try to curl "+url)
    resp = requests.get(url)
    print(resp.text)
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
    print("func check_version, try to curl "+url)
    resp = requests.get(url)
    print(resp.text)

    if (resp.status_code == 404):
        bot.send_message(message.from_user.id, "Версия "+message.text+" пакета "+ str(chat_id[message.chat.id]['packet'])+" отсутствует в репозитории "+str(chat_id[message.chat.id]['type_packet']), reply_markup=markup) 
    else:

        resp_parse = json.loads(resp.text)
        
        adv = get_advisories(resp_parse)
        if adv == "no vuln's":
            bot.send_message(message.from_user.id, 'В указанном пакете нет уязвимостей!',reply_markup=markup)
        else:
            bot.send_message(message.from_user.id, 'В указанном пакете есть уязвимости...')
            #print(advisories[0])
            for i in adv:
                bot.send_message(message.from_user.id, "CVSS скоринг: "+str(i['cvss3Score'])+", CVE: "+str(i['aliases'])+", Описание: "+str(i['title']))
            markup2 = types.ReplyKeyboardMarkup(resize_keyboard=False)
            btn1 = types.KeyboardButton('DoS-не критичен')
            btn2 = types.KeyboardButton('Подобрать версию без уязвимостей (DoS не критичен)')
            btn3 = types.KeyboardButton('Подобрать пакет без уязвимостей (DoS критичен)')
            markup2.add(btn1, btn2, btn3)
            bot.send_message(message.from_user.id, 'обрати внимание на дополнительные опции по анализу', reply_markup=markup2)

def get_advisories(dict):
    print(dict['advisoryKeys'])
    if dict['advisoryKeys']:
        advisories = []
        for i in dict['advisoryKeys']:
            url = 'https://api.deps.dev/v3alpha/advisories/'+i['id']
            resp = requests.get(url)
            resp_parse = json.loads(resp.text)
            advisories.append(resp_parse)
        return advisories
    else:
        return "no vuln's"



bot.polling(none_stop=True, interval=0) 
