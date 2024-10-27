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
        data += '###'  # Using a delimiter to separate the hidden message
        data_bits = ''.join(format(ord(i), '08b') for i in data)

        data_index = 0
        pixels = np.array(img)

        if len(data_bits) > pixels.size:
            raise ValueError("Data is too large to encode in the provided image.")

        for i in range(pixels.shape[0]):
            for j in range(pixels.shape[1]):
                if data_index < len(data_bits):
                    # Modify the least significant bit of the red channel
                    pixels[i, j][0] = (pixels[i, j][0] & 0xFE) | int(data_bits[data_index])
                    data_index += 1
                else:
                    break

        encoded_image = Image.fromarray(pixels)

        # Save the encoded image in the media/uploads directory
        fs = FileSystemStorage(location=os.path.join(settings.MEDIA_ROOT, 'uploads'))
        encoded_image_name = f"encoded_{os.path.basename(image_path)}"
        buffer = BytesIO()
        encoded_image.save(buffer, format='PNG')  # Save as PNG to prevent compression artifacts
        buffer.seek(0)

        # Save the encoded image using FileSystemStorage
        fs.save(encoded_image_name, buffer)
        return fs.url(encoded_image_name)  # Return the URL to access the image

    except Exception as e:
        return str(e)  # Return the error message for debugging

def decode_data_from_image(image_path):
    img = Image.open(image_path)
    pixels = np.array(img)
    binary_data = ""

    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            binary_data += str(pixels[i, j][0] & 1)

    # Split binary data into bytes and convert
    message_bits = [binary_data[i:i + 8] for i in range(0, len(binary_data), 8)]
    decoded_message = ""
    for byte in message_bits:
        decoded_message += chr(int(byte, 2))
        if decoded_message[-3:] == '###':  # Your delimiter
            break

    return decoded_message[:-3]  # Remove delimiter


@login_required(login_url='login')
def send_message(request):
    if request.method == 'POST':
        recipient_username = request.POST.get('recipient')
        hidden_message = request.POST.get('hidden_message')
        image = request.FILES.get('image')  # Get the uploaded image file

        recipient = get_object_or_404(User, username=recipient_username)

        if image:
            # Save the image directly in the media/uploads directory
            fs = FileSystemStorage(location=os.path.join(settings.MEDIA_ROOT, 'uploads'))
            filename = fs.save(image.name, image)
            uploaded_file_path = fs.path(filename)  # Get the file path

            try:
                # Encode the hidden message in the image
                encoded_image_url = encode_data_in_image(uploaded_file_path, hidden_message)

                # Save the message
                message = Message(sender=request.user, recipient=recipient, image=encoded_image_url, hidden_message=hidden_message)
                message.save()

            except Exception as e:
                # Handle any error that occurs during encoding or saving
                return render(request, 'send_message.html', {'error': f'An error occurred: {str(e)}'})

            finally:
                # Clean up the temporary image if needed
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
    # Get the message object
    message = get_object_or_404(Message, id=message_id)
    # Path to the image
    image_path = message.image.path

    try:
        # Decode the message
        decoded_message = decode_data_from_image(image_path)
        return JsonResponse({'decoded_message': decoded_message})
    except Exception as e:
        return JsonResponse({'error': str(e)})
@login_required(login_url='login')
def delete_message(request, message_id):
    message = get_object_or_404(Message, id=message_id)

    # Check if the logged-in user is either the sender or recipient
    if message.sender == request.user or message.recipient == request.user:
        if request.method == "POST":
            # Proceed with deletion if confirmed
            message.delete()
            return redirect('view_messages')  # Redirect to the messages view
        else:
            # Render confirmation template
            context = {'message': message}
            return render(request, 'confirm_delete.html', context)
    else:
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

@login_required
def user_logout(request):
    logout(request)
    return redirect('login')

def base(request):
    return render(request, 'base.html')