from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import Message
from django.contrib.auth.decorators import login_required
from django.core.files.storage import FileSystemStorage
from django.core.paginator import Paginator
import os
from PIL import Image
import numpy as np
from io import BytesIO

def encode_data_in_image(image_path, data):
    try:
        img = Image.open(image_path)
        img = img.convert('RGB')
        data += '###'  # Delimiter to separate the hidden message
        data_bits = ''.join(format(ord(i), '08b') for i in data)

        if len(data_bits) > img.size[0] * img.size[1] * 3:  # Each pixel has 3 channels
            raise ValueError("Data is too large to encode in the provided image.")

        pixels = np.array(img)
        data_index = 0

        for i in range(pixels.shape[0]):
            for j in range(pixels.shape[1]):
                for k in range(3):  # Iterate over R, G, B channels
                    if data_index < len(data_bits):
                        pixels[i, j, k] = (pixels[i, j, k] & 0xFE) | int(data_bits[data_index])
                        data_index += 1

        encoded_image = Image.fromarray(pixels)

        # Save the encoded image to media/uploads
        uploads_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
        os.makedirs(uploads_dir, exist_ok=True)
        encoded_image_name = f"encoded_{os.path.basename(image_path)}"
        encoded_image_path = os.path.join(uploads_dir, encoded_image_name)

        encoded_image.save(encoded_image_path, format='PNG')  # Save as PNG
        return encoded_image_path  # Return the absolute path to the encoded image

    except Exception as e:
        return str(e)  # Return error message for debugging


def decode_data_from_image(image_path):
    try:
        img = Image.open(image_path)
        pixels = np.array(img)
        binary_data = ""

        for i in range(pixels.shape[0]):
            for j in range(pixels.shape[1]):
                for k in range(3):  # Extract from R, G, B channels
                    binary_data += str(pixels[i, j, k] & 1)

        # Split binary data into bytes and decode
        message_bits = [binary_data[i:i + 8] for i in range(0, len(binary_data), 8)]
        decoded_message = ""
        for byte in message_bits:
            decoded_message += chr(int(byte, 2))
            if decoded_message.endswith('###'):  # Check for delimiter
                return decoded_message[:-3]  # Remove delimiter

        return "No hidden message found."

    except Exception as e:
        return str(e)  # Return error message for debugging



@login_required(login_url='login')
def send_message(request):
    if request.method == 'POST':
        recipient_username = request.POST.get('recipient')
        hidden_message = request.POST.get('hidden_message')
        image = request.FILES.get('image')

        recipient = get_object_or_404(User, username=recipient_username)

        if image:
            # Save the uploaded image to media/uploads
            uploads_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
            os.makedirs(uploads_dir, exist_ok=True)
            uploaded_file_path = os.path.join(uploads_dir, image.name)

            with open(uploaded_file_path, 'wb+') as destination:
                for chunk in image.chunks():
                    destination.write(chunk)

            try:
                # Encode the hidden message in the image
                encoded_image_path = encode_data_in_image(uploaded_file_path, hidden_message)
                encoded_image_relative_path = os.path.relpath(encoded_image_path, settings.MEDIA_ROOT)

                # Save the message
                message = Message(
                    sender=request.user,
                    recipient=recipient,
                    image=encoded_image_relative_path,
                    hidden_message=hidden_message
                )
                message.save()

            except Exception as e:
                return render(request, 'send_message.html', {'error': f'Error: {str(e)}'})

            finally:
                # Clean up the original uploaded file
                if os.path.exists(uploaded_file_path):
                    os.remove(uploaded_file_path)
        else:
            return render(request, 'send_message.html', {'error': 'Please upload an image.'})

        return redirect('home')

    return render(request, 'send_message.html')


@login_required(login_url='login')
def view_messages(request):
    # Get the messages sent to the logged-in user
    received_messages = Message.objects.filter(recipient=request.user)
    # Get the messages sent by the logged-in user
    sent_messages = Message.objects.filter(sender=request.user)

    # Paginate the received messages
    paginator = Paginator(received_messages, 10)  # Show 10 messages per page
    page_number = request.GET.get('page')
    paged_messages = paginator.get_page(page_number)

    context = {
        'received_messages': paged_messages,
        'sent_messages': sent_messages,
    }
    return render(request, 'view_messages.html', context)
@login_required(login_url='login')
def decode_message(request, message_id):
    message = get_object_or_404(Message, id=message_id)

    # Construct the absolute path to the image
    image_path = os.path.join(settings.MEDIA_ROOT, message.image.name)

    try:
        decoded_message = decode_data_from_image(image_path)
        return JsonResponse({'decoded_message': decoded_message})
    except Exception as e:
        return JsonResponse({'error': str(e)})

@login_required(login_url='login')
def delete_message(request, message_id):
    message = get_object_or_404(Message, id=message_id)

    # Ensure only the sender or recipient can delete
    if message.sender == request.user or message.recipient == request.user:
        if request.method == "POST":
            # Delete the message and redirect
            message.delete()
            return redirect('view_messages')
        else:
            # Redirect back if the request is not POST
            return redirect('view_messages')
    else:
        # Show error if the user isn't authorized
        return render(request, 'error.html', {'error': 'You do not have permission to delete this message.'})


def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # Automatically log in the user after registration
            return redirect('home')
    else:
        form = UserCreationForm()
    return render(request, 'register.html', {'form': form})

def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')
    return render(request, 'login.html')

@login_required(login_url='login')
def home(request):
    return render(request, 'home.html')

@login_required(login_url='login')
def user_logout(request):
    logout(request)
    return redirect('login')

def base(request):
    return render(request, 'base.html')