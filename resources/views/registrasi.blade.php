@extends('layouts.main')

@section('aside')

<div class="flex flex-col px-4 mx-auto w-full h-full justify-center items-center lg:px-8 xl:px-4 xl:mb-[50px]">
    <img src="{{ asset('images/main-picture.svg') }} " class="size-64 lg:size-96" alt="">
    <div class="card bg-color-6 border border-color-5 text-color-9 mx-auto rounded-3xl max-w-96 md:max-w-[29.688rem] md:min-h-[12.5rem]">
        <div class="card-body">
            <p class="font-bold text-xl md:text-2xl lg:text-xl xl:text-2xl">Berbagi, Mendukung, Berkembang.</p>
            <p class="text-justify text-color-4 md:text-base lg:text-sm xl:text-base">Bersama, kita hadapi tantangan dan jaga kesehatan mental. Setiap langkah kecil membawa kita menuju masa depan yang lebih cerah!</p>
        </div>
    </div>
</div>

@endsection

@section('main')

<div class="flex flex-col justify-center items-center w-full h-auto">
    <h1 class="font-bold text-3xl lg:text-4xl font-color-1 mb-3">Registrasi Akun</h1>
    
    <form class="flex flex-col justify-center items-center w-full" action="{{ route('registration') }}" method="post">
        @csrf

        <label class="form-control w-full max-w-sm">
            <div class="label">
                <span class="label-text text-base font-medium font-color-1">Nama</span>
            </div>
            <input type="text" name="nama" placeholder="Masukkan nama anda" class="input input-bordered bg-color-6  border-color-2 w-full max-w-sm font-base text-color-2" />
        </label>
        @error('nama')
            <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
        @enderror

        <label class="form-control w-full max-w-sm">
            <div class="label">
                <span class="label-text text-base font-medium font-color-1">Email</span>
            </div>
            <input type="email" name="email" placeholder="Masukkan email anda" class="input input-bordered bg-color-6  border-color-2 w-full max-w-sm font-base text-color-2" />
        </label>
        @error('email')
            <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
        @enderror

        <label class="form-control w-full max-w-sm">
            <div class="label">
                <span class="label-text">Jenis Kelamin</span>
            </div>
            <select name="jenis_kelamin" class="select select-bordered bg-color-6  border-color-2 font-base">
                <option disabled selected>Pilih jenis kelamin</option>
                <option value="laki laki">Laki-laki</option>
                <option value="perempuan">Perempuan</option>
            </select>
        </label>
        @error('jenis_kelamin')
            <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
        @enderror

        <label class="form-control w-full max-w-sm">
                <div class="label">
                    <span class="label-text text-base font-medium font-color-1">Tanggal Lahir</span>
                </div>
            <input type="date" name="tanggal_lahir" placeholder="Tanggal Lahir" class="input input-bordered bg-color-6  border-color-2 w-full max-w-sm font-base text-color-2" />
        </label>
        @error('tanggal_lahir')
            <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
        @enderror

        <label class="form-control w-full max-w-sm">
            <div class="label">
                <span class="label-text text-base font-medium font-color-1">Password</span>
            </div>
            <input type="password" name="password" placeholder="Masukkan password" class="input input-bordered bg-color-6 border-color-2 w-full max-w-sm font-base text-color-2" />
        </label>
        @error('password')
            <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
        @enderror
        
        <label class="form-control w-full max-w-sm">
            <div class="label">
                <span class="label-text text-base font-medium font-color-1">Verifikasi Password</span>
            </div>
            <input type="password" name="password_confirmation" placeholder="Masukkan verifikasi password" class="input input-bordered bg-color-6 border-color-2 w-full max-w-sm font-base text-color-2" />
        </label>
        @error('password_confirmation')
            <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
        @enderror

        <button class="btn w-full max-w-sm bg-color-3 text-base-100 mt-10">Daftar</button>
    </form>

    <p class="text-color-2 mt-10">
        Sudah memiliki akun?
        <a class="text-color-3 hover:font-underline" href="/login">
            Masuk Sekarang!
        </a>
    </p>

</div>

@endsection