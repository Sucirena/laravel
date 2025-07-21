@extends('layouts.main_admin')

@section('main')

<div class="w-full p-5 rounded-2xl">

    <a href="/super-admin/user-tenaga-ahli" class="btn btn-sm bg-color-3 text-color-putih hover:bg-opacity-75 border-0">
        <img class="w-6 h-6" src="{{ asset("icons/back.svg")}}" alt="">
        Kembali
    </a>

    <h1 class="font-bold text-3xl text-center">Tambah Data Tenaga Ahli</h1>
    <div class="pt-10 p-10">

        <form action="{{ route('user-tenaga-ahli.store') }}" method="post" enctype="multipart/form-data">
            @csrf
            @method('POST')

            <input type="hidden" name="role" value="tenaga ahli">

            <label class="form-control w-full mt-5">
                <span class="label-text font-medium text-base pb-1">Email</span>
                <input type="email" name="email" placeholder="Masukkan email Anda" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('email')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <label class="form-control w-full mt-5">
                <span class="label-text font-medium text-base pb-1">Password</span>
                <input type="password" name="password" placeholder="Masukkan password Anda" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('password')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <label class="form-control w-full mt-5">
                <span class="label-text font-medium text-base pb-1">Nama</span>
                <input type="text" name="nama" placeholder="Masukkan nama lengkap Anda" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('nama')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <label class="form-control w-full mt-5">
                <span class="label-text font-medium text-base pb-1">Jenis Kelamin</span>
                <select name="jenis_kelamin" class="select select-bordered w-full  outline outline-1 outline-color-5 bg-color-6 rounded-lg">
                    <option disabled selected>Pilih jenis kelamin</option>
                    <option value="laki laki">Laki - Laki</option>
                    <option value="perempuan">Perempuan</option>
                </select>
            </label>
            @error('jenis_kelamin')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <label class="form-control w-full mt-5">
                <span class="label-text font-medium text-base pb-1">Tanggal Lahir</span>
                <input type="date" name="tanggal_lahir" placeholder="Type here" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('tanggal_lahir')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

			<label class="form-control w-full pt-5">
                <div class="label">
                    <span class="label-text font-medium text-base">Foto Profil</span>
                </div>
                <input type="file" name="foto_profil" class="file:bg-color-3 file:text-white file:text-sm file:border-none file:h-[3rem] file:mr-4 file:px-4 file:rounded-l-lg file:font-semibold file:uppercase border border-color-5 rounded-lg w-full bg-color-6">
            </label>
            @error('foto_profil')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror
			
			<label class="form-control w-full pt-5 ">
				<span class="label-text font-medium text-base pb-1">Nomor STR (Surat Tanda Registrasi )</span>
				<input type="text" name="nomor_str" placeholder="Masukkan nomor STR anda" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
			</label>
			@error('nomor_str')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

			<label class="form-control w-full pt-5 ">
				<span class="label-text font-medium text-base pb-1">Spesialisasi</span>
				<input type="text" name="spesialisasi" placeholder="Spesialisasi Anda" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
			</label>
			@error('spesialisasi')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

			<label class="form-control w-full pt-5 ">
				<span class="label-text font-medium text-base pb-1">Jadwal Praktik</span>
				<input type="text" name="jadwal_aktif" placeholder="Masukkan jadwal praktik anda" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
			</label>
			@error('jadwal_aktif')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

			<label class="form-control w-full pt-5 ">
				<span class="label-text font-medium text-base pb-1">Lokasi Praktik</span>
				<input type="text" name="lokasi_praktik" placeholder="Masukkan lokasi praktik anda" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
			</label>
			@error('lokasi_praktik')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <label class="form-control w-full pt-5 ">
				<span class="label-text font-medium text-base pb-1">Riwayat Pendidikan</span>
				<input type="text" name="riwayat_pendidikan" placeholder="Masukkan riwayat pendidikan Anda" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
			@error('riwayat_pendidikan')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <label class="form-control w-full pt-5">
				<span class="label-text font-medium text-base pb-1">Biaya</span>
				<input type="number" name="biaya_konsultasi" placeholder="Masukkan biaya konsultasi anda" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
			@error('biaya_konsultasi')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

			<input type="hidden" name="tabungan" value="0">
            
            <label class="flex justify-center items-center mt-5">
                <button class="btn bg-color-3 text-white w-48">Tambah</button>
            </label>

        </form>
    </div>

</div>

@endsection