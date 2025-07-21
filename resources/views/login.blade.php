@extends('layouts.main')

@section('aside')
    <div class="flex flex-col px-4 mx-auto w-full h-full justify-center items-center lg:px-8 xl:px-4 xl:mb-[50px]">
        <img src="{{ asset('images/main-picture.svg') }} " class="size-64 lg:size-96" alt="">
        <div
            class="card bg-color-6 border border-color-5 text-color-9 mx-auto rounded-3xl max-w-96 md:max-w-[29.688rem] md:min-h-[12.5rem]">
            <div class="card-body">
                <p class="font-bold text-xl md:text-2xl lg:text-xl xl:text-2xl">Berbagi, Mendukung, Berkembang.</p>
                <p class="text-justify text-xs text-color-4 md:text-base lg:text-sm xl:text-base">Bersama, kita hadapi
                    tantangan dan jaga kesehatan mental. Setiap langkah kecil membawa kita menuju masa depan yang lebih
                    cerah!</p>
            </div>
        </div>
    </div>
@endsection

@section('main')
    <div class="flex flex-col justify-center items-center w-full ">
        <h1 class="font-bold text-4xl font-color-1 mb-3">Masuk</h1>

        <form class="flex flex-col justify-center items-center w-full" action="{{ route('authenticate') }}" method="post">
            @csrf

            <label class="form-control w-full max-w-sm">
                <div class="label">
                    <span class="label-text text-base font-medium font-color-1">Email</span>
                </div>
                <input type="email" name="email" placeholder="Masukkan email"
                    class="input input-bordered bg-color-6  border-color-2 w-full max-w-sm font-base text-color-2" />
                @error('email')
                    <p class="text-red-500 text-sm mt-1">{{ $message }}</p>
                @enderror
            </label>

            <label class="form-control w-full max-w-sm">
                <div class="label">
                    <span class="label-text text-base font-medium font-color-1">Password</span>
                </div>
                <input type="password" name="password" placeholder="Masukkan password"
                    class="input input-bordered bg-color-6  border-color-2 w-full max-w-sm font-base text-color-2" />
                @error('password')
                    <p class="text-red-500 text-sm mt-1">{{ $message }}</p>
                @enderror
            </label>
            <label class="form-control w-full max-w-sm">
                <div class="label">
                    <span class="label-text text-base font-medium font-color-1">Captcha</span>
                </div>
                <div class="flex items-center gap-2">
                    <input type="text" name="captcha" placeholder="Masukkan captcha"
                        class="input input-bordered bg-color-6 border-color-2 w-full max-w-sm font-base text-color-2" />
                    <img src="{{ captcha_src() }}" alt="Captcha Image" id="captchaImage" class="h-10 cursor-pointer"
                        onclick="refreshCaptcha()">
                </div>
                <button type="button" class="btn btn-sm bg-transparent text-black mt-2" onclick="refreshCaptcha()">
                    <i class="fas fa-sync-alt"></i> Refresh Captcha
                </button>
                @error('captcha')
                    <p class="text-red-500 text-sm mt-1">invalid captcha</p>
                @enderror
            </label>

            <button type="submit" class="btn w-full max-w-sm bg-color-3 text-base-100 mt-10">
                Login
            </button>
        </form>

        <p class="text-color-2 mt-10">
            Belum memiliki akun?
            <a href="/registrasi" class="text-color-3 hover:font-underline">
                Daftar Sekarang!
            </a>
        </p>
    </div>

    <script>
        function refreshCaptcha() {
            fetch('/captcha/api')
                .then(response => {
                    console.log(response)
                    return response.json()
                })
                .then(data => {
                    document.getElementById('captchaImage').src = data.img;
                })
                .catch(error => console.error('Error refreshing captcha:', error));
        }
    </script>
@endsection
