@extends('layouts.main_admin2')

@section('main')

<div class="flex flex-col gap-4">

    <div>
        <a href="/content-admin/diskusi" class="btn btn-sm bg-color-3 text-color-putih hover:bg-opacity-75 border-0">
            <img class="w-6 h-6" src="{{ asset("icons/back.svg")}}" alt="">
            Kembali
        </a>
    </div>

    <h1 class="text-[2rem] text-color-1 font-bold">Data Balasan Diskusi - {{ $diskusi->id }}</h1>

    <!-- tabel data balasan -->
    <div class="w-full p-5 rounded-2xl">
        <div class="overflow-y-auto min-h-[calc(100vh-350px)]">
            <table class="table table-xs">
                <thead>
                    <tr class="text-color-1">
                        <th>No</th>
                        <th>Nama Pembalas</th>
                        <th>Isi Balasan</th>
                        <th>Waktu Upload</th>
                        <th>Aksi</th>
                    </tr>
                </thead>

                <tbody>
                    @foreach ($balasan as $key => $item)
                        <tr>
                            <th>{{ ($balasan->currentPage() - 1) * $balasan->perPage() + $key + 1 }}</th>
                            <td>{{ $item->pasien ? $item->pasien->user->email ?? '#userDeleted' : '#userDeleted' }}</td>
                            <td>{{ $item->isi }}</td>
                            <td>{{ $item->created_at }}</td>
                            <td class="flex justify-center gap-2">
                                <!-- Aksi seperti hapus balasan -->
                                <button class="btn bg-red-100 text-red-500 border-red-500" onclick="confirmDeletion({{ $item->id }})">
                                    <img class="w-6 h-6" src="{{ asset('icons/Waste.svg') }}" alt="Delete">
                                </button>
                            </td>
                        </tr>

                        <!-- Form Hapus Balasan -->
                        <form id="delete-form-{{ $item->id }}" action="{{ route('balasan.destroy', $item->id) }}" method="POST">
                            @csrf
                            @method('DELETE')
                        </form>
                    @endforeach
                </tbody>
            </table>

            <!-- Pagination Links -->
            <div class="mt-4">
                {!! $balasan->links() !!}
            </div>
        </div>
    </div>
</div>

@endsection
