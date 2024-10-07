from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import Message
from django.contrib.auth.decorators import login_required
from django.core.files.storage import FileSystemStorage
import os
from PIL import Image
import numpy as np
from io import BytesIO

def encode_data_in_image(image_path, data):
    img = Image.open(image_path)
    img = img.convert('RGB')
    data += '###'  # Using a delimiter to separate the hidden message
    data_bits = ''.join(format(ord(i), '08b') for i in data)

    data_index = 0
    pixels = np.array(img)

    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            if data_index < len(data_bits):
                # Change the least significant bit of the pixel
                pixels[i, j][0] = (pixels[i, j][0] & 0xFE) | int(data_bits[data_index])
                data_index += 1
            else:
                break

    encoded_image = Image.fromarray(pixels)

    # Save the encoded image in the media/uploads directory
    fs = FileSystemStorage(location=os.path.join(settings.MEDIA_ROOT, 'uploads'))
    encoded_image_name = f"encoded_{os.path.basename(image_path)}"
    buffer = BytesIO()
    encoded_image.save(buffer, format='PNG')  # Save as PNG or the desired format
    buffer.seek(0)

    # Save the encoded image using FileSystemStorage
    fs.save(encoded_image_name, buffer)
    return fs.url(encoded_image_name)  # Return the URL to access the image

def decode_data_from_image(image_path):
    try:
        img = Image.open(image_path)
    except FileNotFoundError:
        return "Image file not found or has been deleted."

    pixels = np.array(img)
    binary_data = ""

    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            binary_data += str(pixels[i, j][0] & 1)

    # Split binary data into bytes
    message_bits = [binary_data[i:i + 8] for i in range(0, len(binary_data), 8)]
    decoded_message = ""

    for byte in message_bits:
        decoded_message += chr(int(byte, 2))
        if decoded_message[-3:] == '###':  # Check for our delimiter
            break

    return decoded_message[:-3]  # Remove delimiter

@login_required
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

            # Encode the hidden message in the image
            encoded_image_url = encode_data_in_image(uploaded_file_path, hidden_message)

            # Save the message
            message = Message(sender=request.user, recipient=recipient, image=encoded_image_url, hidden_message=hidden_message)
            message.save()

            # Clean up the temporary image if needed (optional)
            os.remove(uploaded_file_path)
        else:
            return render(request, 'send_message.html', {'error': 'Please upload an image.'})

        return redirect('home')

    return render(request, 'send_message.html')

@login_required
def view_messages(request):
    messages = Message.objects.filter(recipient=request.user)
    decoded_messages = []

    if messages.exists():
        for message in messages:
            # Ensure the file path is relative to MEDIA_ROOT
            image_path = os.path.join(settings.MEDIA_ROOT, message.image.name)  # Get file path
            hidden_message = decode_data_from_image(image_path)  # Decode the message
            decoded_messages.append({
                'sender': message.sender.username,
                'hidden_message': hidden_message,
                'image': message.image.url,  # Use URL to access image in templates
            })
    else:
        decoded_messages = None  # No messages available

    return render(request, 'view_messages.html', {'messages': decoded_messages})

@login_required
def delete_message(request, message_id):
    message = get_object_or_404(Message, id=message_id)

    if message.recipient == request.user:  # Ensure the user can only delete their messages
        # Attempt to delete the image file if it exists
        if os.path.exists(message.image.path):
            os.remove(message.image.path)  # Remove the image file from storage
        else:
            print(f"File not found: {message.image.path}")

        message.delete()  # Delete the message from the database

    return redirect('view_messages')

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
@login_required
def home(request):
    return render(request, 'home.html')

@login_required
def user_logout(request):
    logout(request)
    return redirect('login')

def base(request):
    return render(request, 'base.html')