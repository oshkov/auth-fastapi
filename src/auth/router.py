from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from src.database import get_async_session
from src.auth.utils import create_user, verify_password, create_access_token, get_user_by_email, get_current_user, edit_user
from src.auth.schemas import UserCreate, UserLogin, UserEdit, UserRead


router = APIRouter(
    tags=['Auth']
)


@router.post('/register')
async def register(
    user: UserCreate,
    session = Depends(get_async_session)
):
    try:
        # Проверка пользователя на наличие регистрации
        user_in_db = await get_user_by_email(session, user.email)

        # Ошибка, если пользователь уже зарегистрирован
        if user_in_db:
            response_data = {
                'status': 'error',
                'data': None,
                'detail': 'User already registered'
            }
            return JSONResponse(content=response_data, status_code=409)

        # Запись пользователя в бд
        await create_user(session, user)

        jwt_token = await create_access_token(session, user.email)

        response_data = {
                'status': 'success',
                'data': {
                    'jwt_token': jwt_token,
                    'token_type': 'jwt_token'
                },
                'detail': None
            }
        response = JSONResponse(content=response_data, status_code=200)
        response.set_cookie(key='jwt_token', value=jwt_token, max_age=3600)

        return response

    except Exception as error:
        response_data = {
            'status': 'error',
            'data': str(error),
            'detail': 'Server error'
        }
        return JSONResponse(content=response_data, status_code=500)
    

@router.post('/login')
async def login(
    user: UserLogin,
    session = Depends(get_async_session)
):
    try:
        # Проверка пароля пользователя
        if await verify_password(session, user.email, user.password):
            
            # Создание JWT токена
            jwt_token = await create_access_token(session, user.email)

            response_data = {
                'status': 'success',
                'data': {
                    'jwt_token': jwt_token,
                    'token_type': 'jwt_token'
                },
                'detail': None
            }
            response = JSONResponse(content=response_data, status_code=200)

            # Добавление токена в куки
            response.set_cookie(key='jwt_token', value=jwt_token, max_age=3600)

            return response
        
        # Ошибка авторизации
        else:
            response_data = {
                'status': 'error',
                'data': None,
                'detail': 'Invalid credentials'
            }
            return JSONResponse(content=response_data, status_code=401)

    # Ошибка сервера
    except Exception as error:
        response_data = {
            'status': 'error',
            'data': str(error),
            'detail': 'Server error'
        }
        return JSONResponse(content=response_data, status_code=500)
    

@router.post('/logout')
async def logout():
    try:
        response_data = {
            'status': 'success',
            'data': None,
            'detail': None
        }
        response = JSONResponse(content=response_data)
        response.delete_cookie('jwt_token')

        return response

    except Exception as error:
        response_data = {
            'status': 'error',
            'data': str(error),
            'detail': 'Server error'
        }
        return JSONResponse(content=response_data, status_code=500)
    

@router.post('/edit-profile')
async def edit_profile(
    new_user_data: UserEdit,
    user: UserRead = Depends(get_current_user),
    session = Depends(get_async_session)
):
    try:
        # Проверка на наличие пользователя с таким же email
        user_in_db = await get_user_by_email(session, new_user_data.email)
        if user_in_db and user_in_db.id != user.id:
            response_data = {
                'status': 'error',
                'data': None,
                'detail': 'User with this email already registered'
            }
            response = JSONResponse(content=response_data, status_code=409)

            return response

        # Проверка пароля
        if await verify_password(session, user.email, new_user_data.password):

            # Изменение данных профиля
            await edit_user(session, user, new_user_data)

            # Создание JWT токена
            jwt_token = await create_access_token(session, new_user_data.email)

            response_data = {
                'status': 'success',
                'data': {
                    'jwt_token': jwt_token,
                    'token_type': 'jwt_token'
                },
                'detail': None
            }
            response = JSONResponse(content=response_data, status_code=200)

            # Добавление токена в куки
            response.set_cookie(key='jwt_token', value=jwt_token, max_age=3600)

            return response
        
        else:
            response_data = {
                    'status': 'error',
                    'data': None,
                    'detail': 'Password is incorrect'
                }
            response = JSONResponse(content=response_data, status_code=400)

            return response

    except Exception as error:
        print(error)
        response_data = {
            'status': 'error',
            'data': str(error),
            'detail': 'Server error'
        }
        return JSONResponse(content=response_data, status_code=500)