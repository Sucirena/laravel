@extends('layouts.main_admin2')

@section('main')

<div class="w-full p-5 rounded-2xl">

    <a href="/content-admin/konten-edukatif" class="btn btn-sm bg-color-3 text-color-putih hover:bg-opacity-75 border-0">
        <img class="w-6 h-6" src="{{ asset("icons/back.svg")}}" alt="">
        Kembali
    </a>

    <h1 class="font-bold text-3xl text-center">Detail Data Konten Edukatif</h1>

    <div class="p-10">

        <label class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Judul</span>
            <input readonly value="{{ $kontenEdukatif->judul }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
        </label>

        <label class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Perilis</span>
            <input readonly value="{{ $kontenEdukatif->user->nama }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
        </label>

        <label class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Thumbnail</span>
            <!-- Preview -->
            <div class="w-full p-3">
                <img src="{{ asset('storage/' . $kontenEdukatif->thumbnail) }}" alt="Thumbnail Konten" class="w-32 h-32 object-cover rounded-lg" />
            </div>
        </label>

        <label class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Tipe Konten</span>
            <input readonly value="{{ $kontenEdukatif->tipe }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
        </label>

        <label class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Sumber</span>
            <input readonly value="{{ $kontenEdukatif->sumber }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
        </label>

        @if($kontenEdukatif->tipe == 'artikel')
            <label class="form-control w-full pt-5">
                <span class="label-text font-medium text-base pb-1">Isi Artikel</span>
                <textarea readonly class="textarea textarea-bordered w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg">{{ $kontenEdukatif->isi_artikel }}</textarea>
            </label>
        @endif

        @if($kontenEdukatif->tipe == 'video')
            <label class="form-control w-full pt-5">
                <span class="label-text font-medium text-base pb-1">Link YouTube</span>
                <input readonly value="{{ $kontenEdukatif->link_youtube }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            <!-- Embed YouTube video preview -->
            <div class="w-full pt-5">
                <iframe width="560" height="315" src="https://www.youtube.com/embed/{{ basename($kontenEdukatif->link_youtube) }}" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
            </div>
        @endif

        <label class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Kata Kunci</span>
            <input readonly value="{{ $kontenEdukatif->kataKunci->pluck('nama')->implode(', ') }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
        </label>        

        <label class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Tanggal Dibuat</span>
            <input readonly value="{{ $kontenEdukatif->created_at->format('d M Y, H:i') }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
        </label>

        <label class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Terakhir Update</span>
            <input readonly value="{{ $kontenEdukatif->updated_at->format('d M Y, H:i') }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
        </label>

    </div>
</div>
@endsection
