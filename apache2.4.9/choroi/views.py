from django.http import HttpResponse, Http404
from django.core.context_processors import csrf
from django.shortcuts import render_to_response
from django.contrib.auth import logout
from django.http import HttpResponseRedirect
from django.template import RequestContext
import json
import urllib.parse
from django.views.decorators.csrf import csrf_exempt
from choroi.models import *
from PIL import Image
from io import BytesIO
import copy


@csrf_exempt
def register_page(request):
    if request.method == 'POST':
        try:
            decode = m_decode(request.body)
        except:
            rresponse = dict()
            rresponse['status'] = 'decode_error'
            jresponse = json.dumps(rresponse)
            return HttpResponse(jresponse)
    if UserCheck(decode) == 1:
        m_user = m_USER()
        m_user.U_name = decode['username']
        m_user.U_password = decode['password']
        m_user.U_Email = decode['email']
        m_user.save()
        rresponse = dict()
        rresponse['status'] = 'normal'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)

    elif UserCheck(decode) == 2:
        rresponse = dict()
        rresponse['status'] = 'Username_lenth_invalid'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)

    # elif UserCheck(decode) == 3:
    # rresponse = dict()
    # rresponse['status'] = 'password_are_not_same'
    # jresponse = json.dumps(rresponse)
    #        return HttpResponse(jresponse)

    elif UserCheck(decode) == 4:
        rresponse = dict()
        rresponse['status'] = 'password_lenth_invalid'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)

    elif UserCheck(decode) == 5:
        rresponse = dict()
        rresponse['status'] = 'Email_invalid'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)

    else:
        rresponse = dict()
        rresponse['status'] = 'Unknown error'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)


def square(request, pagestr):  # 需要增加指示位置参数
    c = {}
    c.update(csrf(request))
    try:
        page = int(pagestr)
        message = dict()
        message['status'] = 'normal'
        count = 0
        while count < 8:
            try:
                field = m_IMAGE.objects.order_by('-m_Priority', '-Update_date')[(page-1)*8+count]
                message['image'+str(count)+'_small'] = str(field.I_small)
                message['image'+str(count)+'_big'] = str(field.I_big)
                message['image'+str(count)+'_id'] = str(field.id)
                message['position'] = str(count)
                #message['image'+str(count)+'_small'] = str(m_IMAGE.objects.order_by('Update_date')[(page-1)*8+count].I_small)
                #message['image'+str(count)+'_big'] = str(m_IMAGE.objects.order_by('Update_date')[(page-1)*8+count].I_big)
                #message['image'+str(count)+'_time'] = str(m_IMAGE.objects.order_by('Update_date')[(page-1)*8+count].Update_date)
                count += 1
            except:
                message['status'] = 'no_more_image'
                message['count'] = str(count)
                break
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    except:
        message = dict()
        message['status'] = 'unknown_error'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)


def user_page(request, username):
    try:
        user = User.objects.get(username=username)
    except:
        raise Http404('Requested user not found.')
    bookmarks = user.bookmark_set.all()
    variables = RequestContext(request, {
        'username': username,
        'bookmarks': bookmarks
    })
    return render_to_response('user_page.html', variables)


def logout_page(request):
    logout(request)
    return HttpResponseRedirect('/')


def UserCheck(m_Check):
    m_username = m_Check['username']
    m_password = m_Check['password']
    # m_password2 = m_Check['password2']
    m_Email = m_Check['email']
    if len(m_username) < 1 or len(m_username) > 30:
        return 2  # 用户名长度不合法
    # elif m_password != m_password2:
    # return 3  # 两次输入的密码不一样
    elif len(m_password) < 1 or len(m_password) > 16:
        return 4  # 密码长度不合法
    elif '@' not in m_Email:
        return 5  # 邮箱不合法
    else:
        return 1


@csrf_exempt
def upload(request, username):  # 处理图像
    global image_path
    if request.method == 'POST':
        try:  # 读取字段信息
            image = m_IMAGE()
            image.U_ID_id = m_USER.objects.get(U_name=username).id
            image.Like_number = 0
            image.m_Priority = 20
            image.I_space = 10

        except:
            message = dict()
            message['status'] = 'decode_error'
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)

        try:  # 用form读取图片
            img = imageForm(request.POST, request.FILES)
        except:
            message = dict()
            message['status'] = 'file_load_error'
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)
        try:  # 读取图片地址
            if img.is_valid():
                image_path = img.cleaned_data['file0']

            try:
                image.I_origin = image_path
            except:
                message = dict()
                message['status'] = 'path_save_error'
                jmessage = json.dumps(message)
                return HttpResponse(jmessage)
        except:
            message = dict()
            message['status'] = 'file_path_error'
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)

        try:  # 修改图片分辨率:
            image_big = copy.deepcopy(image_path)
            im_big = Image.open(image_big)
            image_small = copy.deepcopy(image_path)
            im_small = Image.open(image_small)
        except:
            message = dict()
            message['status'] = 'open_img_error'
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)

        try:
            (w, h) = im_big.size
        except:
            message = dict()
            message['status'] = 'read_size_error'
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)
        try:
            h_big = h * 320 / w
            h_small = h * 160 / w
        except:
            message = dict()
            message['status'] = 'size_operation_error'
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)

        out_big = im_big.resize((320, int(h_big)), Image.ANTIALIAS)
        image_file1 = BytesIO()
        out_small = im_small.resize((160, int(h_small)), Image.ANTIALIAS)
        out_big.save(image_file1, 'PNG', quility=90)
        image_file2 = BytesIO()
        out_small.save(image_file2, 'PNG', quility=90)
        image_big.file = image_file1
        image_small.file =image_file2

        try:
            image.I_big = image_big
            image.I_small = image_small
        except:
            message = dict()
            message['status'] = 'save_big_error'
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)

        #try:  # 存储到数据库
        image.save()
        message = dict()
        message['status'] = 'normal'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
        '''except:
            message = dict()
            message['status'] = 'save_error'
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)'''
        '''image = imageForm(request.POST, request.FILES)
        if image.is_valid():
            try:
                headImg = image.cleaned_data['image_path']
            except:
                return HttpResponse('image_path_error')
            try:
                img = m_IMAGE()
                try:
                    img.U_ID_id = 1
                except:
                    return HttpResponse('error')
                img.Like_number = 0
                img.I_space = 10
                img.m_Priority = 0
            except:
                return HttpResponse('save_error')
            try:
                img.I_origin = headImg
            except:
                return HttpResponse('path_error')
            img.save()

            return HttpResponse('upload ok')'''
    else:
        image = imageForm()
    return render_to_response('upload.html', {'image': image})


@csrf_exempt
def login(request):
    if request.method == 'POST':
        try:
            decode = m_decode(request.body)
        except:
            rresponse = dict()
            rresponse['status'] = 'decode_error'
            jresponse = json.dumps(rresponse)
            return HttpResponse(jresponse)

        try:
            user_tempt = m_USER.objects.get(U_name=decode['username'])
        except:
            rresponse = dict()
            rresponse['status'] = 'user_not_exist'
            jresponse = json.dumps(rresponse)
            return HttpResponse(jresponse)
        if user_tempt.U_password == decode['password']:  # 密码吻合
            rresponse = dict()
            rresponse['status'] = 'normal'
            rresponse['username'] = decode['username']
            jresponse = json.dumps(rresponse)
            return HttpResponse(jresponse)

        else:
            rresponse = dict()
            rresponse['status'] = 'password_error'
            jresponse = json.dumps(rresponse)
            return HttpResponse(jresponse)
    else:
        rresponse = dict()
        rresponse['status'] = 'unkown_error'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)


def image_delete(request, username, I_id_str):
    I_id = int(I_id_str)
    try:
        user = m_USER.objects.get(U_name=username)
    except:
        message = dict()
        message['status'] = 'user_not_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    try:
        image = m_IMAGE.objects.get(id=I_id)
    except:
        message = dict()
        message['status'] = 'image_not_exit'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    if image.U_ID_id == user.id:
        image.delete()
        message = dict()
        message['status'] = 'normal'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    else:
        message = dict()
        message['status'] = 'not_own'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)


@csrf_exempt
def password_change(request, username):
    try:
        decode = m_decode(request.body)
    except:
        rresponse = dict()
        rresponse['status'] = 'decode_error'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)

    try:
        user = m_USER.objects.get(U_name=username)
        if user.U_Email != decode['email']:
            rresponse = dict()
            rresponse['status'] = 'Email_not_match'
            jresponse = json.dumps(rresponse)
            return HttpResponse(jresponse)
        elif user.U_password != decode['old_password']:
            rresponse = dict()
            rresponse['status'] = 'old_password_not_match'
            jresponse = json.dumps(rresponse)
            return HttpResponse(jresponse)
        else:
            try:
                user.U_password = decode['new_password']
                user.save()
                rresponse = dict()
                rresponse['status'] = 'normal'
                jresponse = json.dumps(rresponse)
                return HttpResponse(jresponse)
            except:
                rresponse = dict()
                rresponse['status'] = 'password_invalid'
                jresponse = json.dumps(rresponse)
                return HttpResponse(jresponse)
    except:
        rresponse = dict()
        rresponse['status'] = 'user_not_exist'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)


def download_origin(request, m_id):
    try:
        message = dict()
        message['status'] = 'normal'
        message['url'] = str(m_IMAGE.objects.get(id=m_id).I_origin)
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    except:
        message = dict()
        message['status'] = 'error'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)


@csrf_exempt
def blacklist_insert(request, username):
    decode = m_decode(request.body)
    target_name = decode['username']
    try:
        user = m_USER.objects.get(U_name=username).id
        target = m_USER.objects.get(U_name=target_name).id
    except:
        rresponse = dict()
        rresponse['status'] = 'user_or_target_not_exist'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)
    try:
        field = m_BLACKLIST.objects.get(U_ID_from=user, U_ID_to=target)
        rresponse = dict()
        rresponse['status'] = 'already_in_blacklist'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)
    except:
        try:
            m_CONCERN.objects.get(U_ID_from=target, U_ID_to = user).delete()
        except:
            a = 0
        field = m_BLACKLIST()
        try:
            field.U_ID_from_id = user
        except:
            rresponse = dict()
            rresponse['status'] = 'user_not_exist'
            jresponse = json.dumps(rresponse)
            return HttpResponse(jresponse)
        try:
            field.U_ID_to_id = target
        except:
            rresponse = dict()
            rresponse['status'] = 'target_not_exist'
            jresponse = json.dumps(rresponse)
            return HttpResponse(jresponse)
        field.save()
        rresponse = dict()
        rresponse['status'] = 'normal'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)


@csrf_exempt
def blacklist_delete(requset, username):
    decode = m_decode(requset.body)
    target = decode['username']
    try:
        user = m_USER.objects.get(U_name=username).id
        target = m_USER.objects.get(U_name=target).id
    except:
        rresponse = dict()
        rresponse['status'] = 'user_or_target_not_exist'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)

    try:
        m_BLACKLIST.objects.get(U_ID_from=user, U_ID_to=target).delete()
        rresponse = dict()
        rresponse['status'] = 'normal'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)
    except:
        rresponse = dict()
        rresponse['status'] = 'blacklist_not_exist'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)


def show_blacklist(request, username):
    try:
        count = 0
        message = dict()
        message['status'] = 'normal'
        try:
            user = m_USER.objects.get(U_name=username).id
        except:
            message = dict()
            message['status'] = 'user_not_exist'
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)

        while count >= 0:
            try:
                target = m_BLACKLIST.objects.filter(U_ID_from=user).order_by('id')[count].U_ID_to_id
                message['target'+str(count)] = m_USER.objects.get(id=target).U_name
                count += 1
            except:
                message['now'] = count
                break
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    except:
        message = dict()
        message['status'] = 'unknown_error'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)


@csrf_exempt
def concern_insert(request, username):
    decode = m_decode(request.body)
    target_name = decode['username']
    try:
        user = m_USER.objects.get(U_name=username).id
        target = m_USER.objects.get(U_name=target_name).id
    except:
        rresponse = dict()
        rresponse['status'] = 'user_or_target_not_exist'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)
    try:
        field = m_CONCERN.objects.get(U_ID_from=user, U_ID_to=target)
        rresponse = dict()
        rresponse['status'] = 'already_concerned'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)
    except:
        try:
            blacklist = m_BLACKLIST.objects.get(U_ID_from=target, U_ID_to=user)
            rresponse = dict()
            rresponse['status'] = 'you_are_in_the_blacklist'
            jresponse = json.dumps(rresponse)
            return HttpResponse(jresponse)
        except:
            field = m_CONCERN()
            try:
                field.U_ID_from_id = user
            except:
                rresponse = dict()
                rresponse['status'] = 'user_not_exist'
                jresponse = json.dumps(rresponse)
                return HttpResponse(jresponse)
            try:
                field.U_ID_to_id = target
            except:
                rresponse = dict()
                rresponse['status'] = 'target_not_exist'
                jresponse = json.dumps(rresponse)
                return HttpResponse(jresponse)
            field.save()
            rresponse = dict()
            try:
                count = m_IMAGE.objects.filter(U_ID=target).count()
                rresponse['count'] = count
            except:
                message = dict()
                message['status'] = 'count_error'
                jmessage = json.dumps(message)
                return HttpResponse(jmessage)
            rresponse['status'] = 'normal'
            jresponse = json.dumps(rresponse)
            return HttpResponse(jresponse)


@csrf_exempt
def concern_delete(requset, username):
    decode = m_decode(requset.body)
    target_name = decode['username']
    try:
        user = m_USER.objects.get(U_name=username).id
        target = m_USER.objects.get(U_name=target_name).id
    except:
        rresponse = dict()
        rresponse['status'] = 'user_or_target_not_exist'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)

    try:
        m_CONCERN.objects.get(U_ID_from=user, U_ID_to=target).delete()
        rresponse = dict()
        rresponse['status'] = 'normal'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)
    except:
        rresponse = dict()
        rresponse['status'] = 'concern_not_exist'
        jresponse = json.dumps(rresponse)
        return HttpResponse(jresponse)


def show_concern(request, username):
    try:
        count = 0
        message = dict()
        message['status'] = 'normal'
        try:
            user = m_USER.objects.get(U_name=username).id
        except:
            message = dict()
            message['status'] = 'user_not_exist'
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)

        while count != -1:
            try:
                target = m_CONCERN.objects.filter(U_ID_from=user).order_by('id')[count].U_ID_to_id
                message['target'+str(count)] = m_USER.objects.get(id=target).U_name
                count += 1
            except:
                message['now'] = count
                break
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    except:
        message = dict()
        message['status'] = 'unknown_error'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)


@csrf_exempt
def relation_page(request, username):
    decode = m_decode(request.body)
    target_name = decode['username']
    response = dict()
    response['status'] = 'normal'
    try:
        user = m_USER.objects.get(U_name=username).id
        target = m_USER.objects.get(U_name=target_name).id
    except:
        message = dict()
        message['status'] = 'use_or_target_not_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    try:
        concern = m_CONCERN.objects.get(U_ID_from=user, U_ID_to=target)
        response['concern'] = 'true'
    except:
        response['concern'] = 'false'
    try:
        blacklist = m_BLACKLIST.objects.get(U_ID_from=user, U_ID_to=target)
        response['blacklist'] = 'true'
    except:
        response['blacklist'] = 'false'
    '''try:
        count = m_IMAGE.objects.filter(U_ID=target).count()
        response['count'] = count
    except:
        message = dict()
        message['status'] = 'count_error'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)'''
    rresponse = json.dumps(response)
    return HttpResponse(rresponse)


@csrf_exempt
def tag_insert(request, username):
    decode = m_decode(request.body)
    target = int(decode['image_id'])
    tag_text = decode['tag']
    try:
        user = m_USER.objects.get(U_name=username).id
    except:
        message = dict()
        message['status'] = 'user_not_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    try:
        m_TAG.objects.get(U_ID=user, I_ID=target, tag=tag_text)
        message = dict()
        message['status'] = 'tag_already_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    except:
        try:
            tag_field = m_TAG()
            tag_field.U_ID_id = user
            tag_field.I_ID_id = target
            tag_field.tag = tag_text
            tag_field.save()
            message = dict()
            message['status'] = 'normal'
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)
        except:
            message = dict()
            message['status'] = 'save_error'
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)


@csrf_exempt
def tag_delete(requset, username):
    decode = m_decode(requset.body)
    tag_id_str = decode['tag_id']
    try:
        tag_id = int(tag_id_str)
    except:
        message = dict()
        message['status'] = 'int_shift_error'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    try:
        user = m_USER.objects.get(U_name=username).id
    except:
        message = dict()
        message['status'] = 'user_not_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    try:
        m_TAG.objects.get(id=tag_id).delete()
        message = dict()
        message['status'] = 'normal'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    except:
        message = dict()
        message['status'] = 'delete_failed'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)


def tag_show(request, image_id_str):
    image_id = int(image_id_str)
    message = dict()
    count = 0
    message['status'] = 'normal'
    while count < 5:
        try:
            tag = m_TAG.objects.filter(I_ID=image_id)[count]
            message['tag'+str(count)] = tag.tag
            message['tag'+str(count)+'_id'] = tag.id
            count += 1
        except:
            message['status'] = 'no_more_tag'
            message['count'] = str(count)
            break
    message['image_id'] = image_id_str
    jmessage = json.dumps(message)
    return HttpResponse(jmessage)


@csrf_exempt
def image_detail(request, username):
    message = dict()
    try:
        decode = m_decode(request.body)
    except:
        message = dict()
        message['status'] = 'decode_error'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    try:
        user_id = m_USER.objects.get(U_name=username).id
    except:
        message = dict()
        message['status'] = 'user_not_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    try:
        image_id = int(decode['id'])
        message['image_id'] = decode['id']
    except:
        message = dict()
        message['status'] = 'int_change_error'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    try:
        image = m_IMAGE.objects.get(id=image_id)
    except:
        message = dict()
        message['status'] = 'image_not_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    count = 0
    message['tag_status'] = 'normal'
    while count < 5:
        try:
            tag = m_TAG.objects.filter(I_ID=image_id)[count]
            message['tag'+str(count)] = tag.tag
            message['tag'+str(count)+'_id'] = tag.id
            count += 1
        except:
            message['tag_status'] = 'no_more_tag'
            message['count'] = str(count)
            break
    try:
        image_origin = str(image.I_origin)
        message['origin'] = image_origin
        author_id = image.U_ID_id
    except:
        message = dict()
        message['status'] = 'error1'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    try:
        author_name = m_USER.objects.get(id=author_id).U_name
        message['author'] = author_name
    except:
        message = dict()
        message['status'] = 'author_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    try:
        like_number = image.Like_number
        message['like'] =like_number
    except:
        message = dict()
        message['status'] = 'error2'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    try:
        m_LIKE.objects.get(U_ID=user_id, I_ID=image_id)
        is_like = 'true'
    except:
        is_like = 'false'
    try:
        date = image.Update_date
        message['update_date'] = str(date)[:-6]
    except:
        message = dict()
        message['status'] = 'error3'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    message['status'] = 'normal'
    message['is_like'] = is_like
    jmessage = json.dumps(message)
    return HttpResponse(jmessage)


@csrf_exempt
def like_change(request, username, image_id_str):
    image_id = int(image_id_str)
    try:
        user = m_USER.objects.get(U_name=username).id
        image = m_IMAGE.objects.get(id=image_id)
    except:
        message = dict()
        message['status'] = 'user_not_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    try:
        m_LIKE.objects.get(U_ID=user, I_ID=image_id).delete()
        like_number = image.Like_number-1
        image.Like_number = like_number
        image.save()
        message = dict()
        message['status'] = 'normal'
        message['is_like'] = 'false'
        message['like_number'] = like_number
        message['image_id'] = image_id_str
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    except:
        like = m_LIKE()
        like.U_ID_id = user
        like.I_ID_id = image_id
        try:
            like.save()
            like_number = image.Like_number+1
            image.Like_number = like_number
            image.save()
            message = dict()
            message['is_like'] = 'true'
            message['status'] = 'normal'
            message['like_number'] = like_number
            message['image_id'] = image_id_str
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)
        except:
            message = dict()
            message['status'] = 'save_error'
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)


@csrf_exempt
def comment_insert(request, username, image_id_str):
    decode = m_decode(request.body)
    comment_text = decode['comment']
    #comment_text = comment_text.replace('+', ' ')
    try:
        user = m_USER.objects.get(U_name=username).id
    except:
        message = dict()
        message['status'] = 'user_not_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    image_id = int(image_id_str)
    try:
        comment_field = m_COMMENT()
        comment_field.U_ID_id = user
        comment_field.I_ID_id = image_id
        comment_field.Comment = comment_text
        comment_field.save()
        message = dict()
        message['status'] = 'normal'
        count = 0
        while count < 8:
            try:
                comment = m_COMMENT.objects.filter(I_ID=image_id).order_by('id')[count]
                user_id = comment.U_ID_id
                username = m_USER.objects.get(id=user_id).U_name
                message['comment'+str(count)+'_username'] = username
                message['comment'+str(count)+'_text'] = comment.Comment
                message['comment'+str(count)+'_id'] = comment.id
                message['comment'+str(count)+'_date'] = str(comment.Update_date)[:-6]
                count += 1
            except:
                message['status'] = 'no_more_comment'
                message['now'] = count
                break
        message['image_id'] = image_id_str
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    except:
        message = dict()
        message['status'] = 'save_error'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)


def comment_delete(request, username, comment_id_str):
    user = m_USER.objects.get(U_name=username).id
    comment_id = int(comment_id_str)
    try:
        m_COMMENT.objects.get(id=comment_id, U_ID=user).delete()
        message = dict()
        message['status'] = 'normal'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    except:
        message = dict()
        message['status'] = 'delete_failed'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)


def comment_show(request, image_id_str, page_str):
    image_id = int(image_id_str)
    page = int(page_str)
    count = 0
    message = dict()
    message['status'] = 'normal'
    while count < 8:
        try:
            comment = m_COMMENT.objects.filter(I_ID=image_id).order_by('id')[(page-1)*8+count]
            user_id = comment.U_ID_id
            username = m_USER.objects.get(id=user_id).U_name
            message['comment'+str(count)+'_username'] = username
            message['comment'+str(count)+'_text'] = comment.Comment
            message['comment'+str(count)+'_id'] = comment.id
            message['comment'+str(count)+'_date'] = str(comment.Update_date)[:-6]
            count += 1
        except:
            message['status'] = 'no_more_comment'
            message['now'] = count
            break
    message['image_id'] = image_id_str
    jmessage = json.dumps(message)
    return HttpResponse(jmessage)


def big_get(request, image_id_str):
    image_id = int(image_id_str)
    try:
        image_big = str(m_IMAGE.objects.get(id=image_id).I_big)
        message = dict()
        message['image_big'] = image_big
        message['status'] = 'normal'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    except:
        message = dict()
        message['status'] = 'image_not_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)


def origin_get(request, image_id_str):
    image_id = int(image_id_str)
    try:
        image_origin = str(m_IMAGE.objects.get(id=image_id).I_origin)
        message = dict()
        message['image_origin'] = image_origin
        message['status'] = 'normal'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    except:
        message = dict()
        message['status'] = 'image_not_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)


def concerned_image(request, username, page_str):
    page = int(page_str)
    try:
        user = m_USER.objects.get(U_name=username).id
    except:
        message = dict()
        message['status'] = 'user_not_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    message = dict()
    message['status'] = 'normal'
    flag = True
    count_target = 0
    while flag:
        try:
            target = m_CONCERN.objects.filter(U_ID_from=user)[count_target].U_ID_to_id
            if count_target == 0:
                image_field = m_IMAGE.objects.filter(U_ID=target)
                count_target += 1
            else:
                image_field = image_field | m_IMAGE.objects.filter(U_ID=target)
                count_target += 1
        except:
            flag = False
    message['count_target'] = count_target
    count = 0
    while count < 8:
        try:
            field = image_field.order_by('-Update_date')[(page-1)*8+count]
            owner = m_USER.objects.get(id=field.U_ID_id)
            owner_name = owner.U_name
            message['image'+str(count)+'_date'] = str(field.Update_date)[:-6]
            message['image'+str(count)+'_small'] = str(field.I_small)
            message['image'+str(count)+'_big'] = str(field.I_big)
            message['image'+str(count)+'_id'] = str(field.id)
            message['image'+str(count)+'_owner'] = owner_name
            count += 1
        except:
            message['status'] = 'no_more_image'
            message['count'] = str(count)
            break
    jmessage = json.dumps(message)
    return HttpResponse(jmessage)


@csrf_exempt
def search_user(request, page_str):
    decode = m_decode(request.body)
    page = int(page_str)
    search_body = decode['name']
    message = dict()
    message['status'] = 'normal'
    try:
        result = m_USER.objects.filter(U_name__contains=search_body)
    except:
        message = dict()
        message['status'] = 'no_such_user'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    count = 0
    while count < 32:
        try:
            message['target_name'+str(count)] = result.order_by('id')[(page-1)*16+count].U_name
            count += 1
        except:
            message['status'] = 'no_more_user'
            message['now'] = count
            break
    jmessage = json.dumps(message)
    return HttpResponse(jmessage)


@csrf_exempt
def search_by_tag(request, page_str):
    decode = m_decode(request.body)
    page = int(page_str)
    search_body = decode['tag']
    message = dict()
    message['status'] = 'normal'
    I_id = list()
    count1 = 0
    while count1 < 8:
        try:
            tag_field = m_TAG.objects.filter(tag__contains=search_body)[(page-1)*8+count1]
            I_id.append(tag_field.I_ID_id)
            count1 += 1
        except:
            message['status'] = 'no_more_image'
            message['now'] = count1
            break
    count = 0
    for ID in I_id:
        try:
            field = m_IMAGE.objects.get(id=ID)
            message['image'+str(count)+'_small'] = str(field.I_small)
            message['image'+str(count)+'_big'] = str(field.I_big)
            message['image'+str(count)+'_id'] = str(field.id)
            count += 1
        except:
            message['status'] = 'image_detail_error'
            jmessage = json.dumps(message)
            return HttpResponse(jmessage)
    jmessage = json.dumps(message)
    return HttpResponse(jmessage)


def image_of(request, username, target_name, page_str):
    page = int(page_str)
    message = dict()
    message['status'] = 'normal'
    try:
        user = m_USER.objects.get(U_name=username).id
        target = m_USER.objects.get(U_name=target_name).id
    except:
        message = dict()
        message['status'] = 'user_or_target_not_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    count = 0
    while count < 8:
        try:
            field = m_IMAGE.objects.filter(U_ID_id=target).order_by('-Update_date')[(page-1)*8+count]
            message['image'+str(count)+'_small'] = str(field.I_small)
            message['image'+str(count)+'_big'] = str(field.I_big)
            message['image'+str(count)+'_date'] = str(field.Update_date)[:-6]
            message['image'+str(count)+'_id'] = str(field.id)
            count += 1
        except:
            message['status'] = 'no_more_image'
            message['count'] = str(count)
            break
    jmessage = json.dumps(message)
    return HttpResponse(jmessage)


def my_image(request, username, page_str):
    page = int(page_str)
    message = dict()
    message['status'] = 'normal'
    try:
        user = m_USER.objects.get(U_name=username).id
    except:
        message = dict()
        message['status'] = 'user_or_target_not_exist'
        jmessage = json.dumps(message)
        return HttpResponse(jmessage)
    count = 0
    while count < 4:
        try:
            field = m_IMAGE.objects.filter(U_ID_id=user).order_by('-Update_date')[(page-1)*4+count]
            message['image'+str(count)+'_small'] = str(field.I_small)
            message['image'+str(count)+'_big'] = str(field.I_big)
            message['image'+str(count)+'_id'] = str(field.id)
            count += 1
        except:
            message['status'] = 'no_more_image'
            message['count'] = str(count)
            break
    jmessage = json.dumps(message)
    return HttpResponse(jmessage)


def m_decode(message):  # json字符串解码
    decodestr = urllib.parse.unquote(message.decode())
    decodestr = decodestr[11:]
    decode = json.loads(decodestr)
    return decode


def calculate(request):
    count=0
    while count >= 0:
        try:
            image = m_IMAGE.objects.order_by('Update_date')[count]
            image.m_Priority = count + image.Like_number*10
            image.save()
            count += 1
        except:
            break
    return  HttpResponse('normal')