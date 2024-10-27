from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import send_message, view_messages, delete_message, register, user_login, home,base, user_logout

urlpatterns = [
    path('send-message/', send_message, name='send_message'),
    path('view-messages/', view_messages, name='view_messages'),
    path('delete-message/<int:message_id>/', delete_message, name='delete_message'),
    path('register/', register, name='register'),
    path('login/', user_login, name='login'),
    path('home/', home, name='home'),
    path('', base, name='base'),
    path('logout/', user_logout, name='logout'),
] 

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) 
