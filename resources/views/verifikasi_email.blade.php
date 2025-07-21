@extends('layouts.main')

@section('aside')

    <div class="flex flex-col mx-auto w-full justify-center items-center mb-[50px] h-full">
        <img src=" {{ asset('images/main-picture.svg') }} " class="max-h-[500px] max-w-[500px]" alt="">
        <div class="card max-w-[475px] max-h-[200px] bg-color-6 border border-color-5 text-color-9 mx-auto">
            <div class="card-body">
                <p class="font-bold text-2xl">Berbagi, Mendukung, Berkembang.</p>
                <p class="text-base text-justify">Bersama, kita hadapi tantangan dan jaga kesehatan mental. Setiap langkah kecil membawa kita menuju masa depan yang lebih cerah!</p>
            </div>
        </div>
    </div>

@endsection

@section('main')

<div class="flex flex-col w-full h-full justify-center bg-color-8 border shadow-sm rounded-xl p-4 md:p-5 text-center">
    <div class="flex flex-col gap-5 px-10 w-full text-left text-color-1">
        <h1 class="text-2xl font-bold text-gray-800 mb-4">Verifikasi kode OTP</h1>
        <p class="text-gray-600 mb-4">Masukkan kode OTP yang telah dikirimkan ke email anda.</p>

        <div class="flex flex-col items-center gap-5">
            <form method="POST" action="{{ route('otp.verify') }}" id="otpForm" class="flex flex-col items-center gap-5 w-full">
                @csrf
                <div class="flex gap-2">
                    <!-- Input OTP -->
                    <input type="text" maxlength="1" class="otp-box w-12 h-12 text-center text-xl font-bold border-2 border-gray-300 rounded-md bg-gray-100 focus:ring focus:ring-blue-300 focus:border-blue-500 outline-none" autofocus required>
                    <input type="text" maxlength="1" class="otp-box w-12 h-12 text-center text-xl font-bold border-2 border-gray-300 rounded-md bg-gray-100 focus:ring focus:ring-blue-300 focus:border-blue-500 outline-none" required>
                    <input type="text" maxlength="1" class="otp-box w-12 h-12 text-center text-xl font-bold border-2 border-gray-300 rounded-md bg-gray-100 focus:ring focus:ring-blue-300 focus:border-blue-500 outline-none" required>
                    <input type="text" maxlength="1" class="otp-box w-12 h-12 text-center text-xl font-bold border-2 border-gray-300 rounded-md bg-gray-100 focus:ring focus:ring-blue-300 focus:border-blue-500 outline-none" required>
                    <input type="text" maxlength="1" class="otp-box w-12 h-12 text-center text-xl font-bold border-2 border-gray-300 rounded-md bg-gray-100 focus:ring focus:ring-blue-300 focus:border-blue-500 outline-none" required>
                    <input type="text" maxlength="1" class="otp-box w-12 h-12 text-center text-xl font-bold border-2 border-gray-300 rounded-md bg-gray-100 focus:ring focus:ring-blue-300 focus:border-blue-500 outline-none" required>
                </div>
                @error('otp_code')
                    <p class="text-red-500 text-sm mt-2">{{ $message }}</p>
                @enderror
                <input type="hidden" name="otp_code" id="otp_code">
                <button type="submit" class="btn bg-color-3 text-white w-fit">
                    Verifikasi OTP
                </button>
            </form>

            <form method="POST" action="{{ route('otp.resend') }}" class="flex flex-col gap-1 items-center">
                @csrf
                <span id="countdown" class="text-gray-600"></span>
                <button type="submit" id="resendButton" class="p-0 text-blue-600 hover:underline disabled:text-gray-400 disabled:cursor-not-allowed">
                    Kirim ulang OTP
                </button>
            </form>
        </div>
    </div>
</div>

<script>
    document.addEventListener("DOMContentLoaded", function () {
        const otpExpiresAt = {{ $otpExpiresAt ?? 'null' }} * 1000; // Convert to milliseconds
        const countdownElement = document.getElementById("countdown");
        const resendButton = document.getElementById("resendButton");
        const otpInputs = document.querySelectorAll(".otp-box");

        // Atur tampilan awal tombol resend
        const disableResendButton = () => {
            resendButton.disabled = true;
            resendButton.classList.add('text-gray-400', 'cursor-not-allowed'); // Ubah gaya tombol menjadi "mati"
            resendButton.classList.remove('text-blue-600', 'hover:underline'); // Hilangkan gaya hover
        };

        const enableResendButton = () => {
            resendButton.disabled = false;
            resendButton.classList.remove('text-gray-400', 'cursor-not-allowed'); // Aktifkan gaya tombol
            resendButton.classList.add('text-blue-600', 'hover:underline'); // Kembalikan gaya hover
        };

        // Inisialisasi tombol resend ke kondisi awal (disabled jika ada waktu tersisa)
        if (otpExpiresAt && otpExpiresAt > new Date().getTime()) {
            disableResendButton();
        } else {
            enableResendButton();
        }

        // Countdown OTP
        if (otpExpiresAt) {
            const interval = setInterval(() => {
                const now = new Date().getTime();
                const distance = otpExpiresAt - now;

                if (distance > 0) {
                    const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                    const seconds = Math.floor((distance % (1000 * 60)) / 1000);
                    countdownElement.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
                    disableResendButton(); // Pastikan tombol tetap dinonaktifkan
                } else {
                    countdownElement.textContent = "Masih belum mendapatkan kode? Klik dibawah ini.";
                    enableResendButton(); // Aktifkan tombol
                    clearInterval(interval);
                }
            }, 1000);
        } else {
            countdownElement.textContent = "OTP is no longer valid.";
        }

        // Logika Input OTP
        otpInputs.forEach((input, index) => {
            input.addEventListener("input", (e) => {
                if (e.target.value.length === 1 && index < otpInputs.length - 1) {
                    otpInputs[index + 1].focus(); // Pindah ke input berikutnya
                }
            });

            input.addEventListener("keydown", (e) => {
                if (e.key === "Backspace" && input.value === "" && index > 0) {
                    otpInputs[index - 1].focus(); // Pindah ke input sebelumnya
                }
            });

            // Blok input selain angka
            input.addEventListener("keypress", (e) => {
                if (!/[0-9]/.test(e.key)) {
                    e.preventDefault();
                }
            });

            // Tangani Paste dengan Filter Non-Angka
            input.addEventListener("paste", (e) => {
                e.preventDefault();
                const pasteData = e.clipboardData.getData("text");

                // Filter hanya angka
                const pasteArray = pasteData.split("").filter(char => /[0-9]/.test(char));

                // Distribusi karakter ke input
                pasteArray.forEach((char, pasteIndex) => {
                    if (index + pasteIndex < otpInputs.length) {
                        otpInputs[index + pasteIndex].value = char; // Masukkan angka ke input
                        if (index + pasteIndex < otpInputs.length - 1) {
                            otpInputs[index + pasteIndex + 1].focus(); // Pindah fokus ke input berikutnya
                        }
                    }
                });
            });
        });

        // Gabungkan nilai OTP sebelum form dikirim
        const otpForm = document.getElementById("otpForm");
        const otpHiddenInput = document.getElementById("otp_code");

        otpForm.addEventListener("submit", (e) => {
            const otpValue = Array.from(otpInputs).map(input => input.value).join("");
            otpHiddenInput.value = otpValue; // Set nilai ke input hidden

            // Validasi: Jika OTP tidak lengkap, cegah pengiriman form
            if (otpValue.length < otpInputs.length) {
                e.preventDefault();
                alert("Harap isi semua kotak OTP.");
            }
        });
    });
</script>
@endsection