@extends('layouts.main_admin')

@section('main')

    <div class="flex flex-col gap-4">
        <h1 class="text-[2rem] text-color-1 font-bold">Data Subscription Plan</h1>
        <div class="grid grid-cols-4 gap-6">

            @foreach ($plans as $key => $plan )
            <div class="col-span-4 flex flex-col items-center bg-color-6 border-[1px] border-color-5 w-full p-4 rounded-2xl gap-4">
                <h1 class="text-[32px] font-medium text-color-1">{{ $plan->name }}</h1>
        
                <!-- Form untuk update plan -->
                <form action="{{ route('subscription.update', $plan->id) }}" method="POST" enctype="multipart/form-data" class="flex flex-col items-center w-full">
                    @csrf
                    @method('PUT') <!-- Method PUT untuk update -->
        
                    <div class="flex w-full gap-3">
                        <label class="form-control w-full">
                            <span class="label-text font-medium text-base pb-1">Nama Paket</span>
                            <input type="text" name="name" value="{{ $plan->name }}" placeholder="Masukkan nama paket" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
                        </label>
                        @error('name')
                            <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
                        @enderror
        
                        <label class="form-control w-full">
                            <span class="label-text font-medium text-base pb-1">Harga Paket</span>
                            <input type="number" min="0" name="price" value="{{ $plan->price }}" placeholder="Masukkan harga paket" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
                        </label>
                        @error('price')
                            <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
                        @enderror
        
                        <label class="form-control w-full">
                            <span class="label-text font-medium text-base pb-1">Durasi Paket</span>
                            <input type="number" min="1" name="duration" value="{{ $plan->duration }}" placeholder="Masukkan durasi paket" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
                        </label>
                        @error('duration')
                            <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
                        @enderror
                    </div>
        
                    <!-- Tombol Update -->
                    <button type="submit" class="btn w-fit bg-color-3 text-white text-base mt-4">
                        Simpan perubahan
                    </button>
                </form>
            </div>
            @endforeach

        </div>
    </div>

@endsection