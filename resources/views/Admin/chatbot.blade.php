@extends('layouts.main_admin')

@section('main')

    <div class="flex flex-col gap-4">
        <h1 class="text-[2rem] text-color-1 font-bold">Model Chatbot</h1>
        <div class="grid grid-cols-4 gap-6">
            <div class="col-span-4 flex flex-col items-center bg-color-6 border-[1px] border-color-5 w-full py-16 px-4 rounded-2xl gap-4">
                <h1 class="text-[32px] font-medium text-color-1">Model Chatbot Lite</h1>
                <p class="text-color-1">Masukkan dataset dengan format yang sesuai untuk memperbarui kualitas dari model chatbot lite.</p>

                <!-- Form untuk update dataset -->
                <form action="{{ route('chatbotLite.updateDataset') }}" method="POST" enctype="multipart/form-data" class="flex flex-col items-center w-full">
                    @csrf
                    <label class="form-control w-full">
                        <div class="label">
                            <span class="label-text font-medium text-base">Model Chatbot</span>
                        </div>
                        <input type="file" name="dataset" class="file:bg-color-3 file:text-white file:text-sm file:border-none file:h-[3rem] file:mr-4 file:px-4 file:rounded-l-lg file:font-semibold file:uppercase border border-color-5 rounded-lg w-full bg-color-6">
                    </label>
                    @error('dataset')
                        <p class="text-red-500 text-sm mt-2">{{ $message }}</p>
                    @enderror
                    <!-- Tombol Update -->
                    <button type="submit" class="btn w-fit bg-color-3 text-white text-base mt-4">
                        Update Model
                    </button>
                </form>
            </div>
        </div>
    </div>

@endsection