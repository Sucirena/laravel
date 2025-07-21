@extends('layouts.main_admin')

@section('main')

<!-- halaman pendapatan admin -->
<div class="flex flex-col gap-6">
    <h1 class="text-[2rem] text-color-1 font-bold">Data Pendapatan</h1>

    <!-- bagian total pendapatan -->
    <div class="flex flex-col items-center bg-color-6 border-[1px] border-color-5 w-full py-16 rounded-2xl gap-4">
        <h1 class="text-[32px] font-medium text-color-1">Total Pendapatan</h1>
        <p class="text-color-1 text-[4rem] font-bold">Rp. 5.170.000.000.000</p>
        <!-- tombol penarikan -->
        <button class="btn btn-wide bg-color-3 text-white text-base">
            Penarikan
        </button>
        <!-- tombol penarikan -->
    </div>
    <!-- bagian total pendapatan -->

    <!-- riwayat penarikan -->
    {{-- <div class="flex flex-col w-full border-[1px] border-color-4 rounded-2xl p-5 gap-6">
        <h1 class="text-2xl text-color-1 font-bold">Riwayat Penarikan</h1>
        <div class="overflow-y-scroll w-full h-80 flex flex-col gap-4">
            <div class="grid grid-rows-1 items-center gap-4">
                
                <!-- card 1 -->
                <div class="flex justify-between bg-color-6 border-[1px] border-color-5 rounded-2xl p-6">
                    <div class="flex flex-col">
                        <span class="text-color-1 font-bold">Jumlah</span>
                        <span class="text-color-2">Rp. 5.000.000.000</span>
                    </div>
                    <div class="flex flex-col">
                        <span class="text-color-1 font-bold">Tanggal</span>
                        <span class="text-color-2">Senin, 17 Oktober 2024</span>
                    </div>
                    <div>
                        <!-- dropdown action -->
                        <div class="dropdown dropdown-end">
                            <div class="btn btn-ghost m-1">
                                <svg
                                    xmlns="http://www.w3.org/2000/svg"
                                    fill="none"
                                    viewBox="0 0 24 24"
                                    class="inline-block h-5 w-5 stroke-current">
                                    <path
                                    stroke-linecap="round"
                                    stroke-linejoin="round"
                                    stroke-width="2"
                                    d="M5 12h.01M12 12h.01M19 12h.01M6 12a1 1 0 11-2 0 1 1 0 012 0zm7 0a1 1 0 11-2 0 1 1 0 012 0zm7 0a1 1 0 11-2 0 1 1 0 012 0z"></path>
                                </svg>
                            </div>
                            <ul class="flex flex-row gap-2 dropdown-content menu bg-base-100 rounded-box z-[1] min-w-max p-2 shadow">
                                <li>
                                    <!-- tombol info -->
                                    <a class="btn bg-blue-100 text-blue-500 border-blue-500 hover:bg-blue-300" href="#">
                                        <img class="w-6 h-6" src="{{ asset("icons/Info.svg")}}" alt="">
                                    </a>
                                </li>
                                <li>
                                    <!-- tombol edit -->
                                    <a class="btn bg-green-100 text-green-500 border-green-500 hover:bg-green-300" href="#">
                                        <img class="w-6 h-6" src="{{ asset("icons/Edit.svg")}}" alt="">
                                    </a>
                                </li>
                                <li>
                                    <!-- tombol hapus -->
                                    <a class="btn bg-red-100 text-red-500 border-red-500 hover:bg-red-300" href="#">
                                        <img class="w-6 h-6" src="{{ asset("icons/Waste.svg")}}" alt="">
                                    </a>
                                </li>
                            </ul>
                        </div>
                        <!-- dropdown action -->
                        
                    </div>
                </div>
                <!-- card 1 -->

            </div>
        </div>
    </div> --}}
    <!-- riwayat penarikan -->

    <!-- riwayat pemasukan-->
    {{-- <div class="flex flex-col w-full border-[1px] border-color-4 rounded-2xl p-5 gap-6">
        <h1 class="text-2xl text-color-1 font-bold">Riwayat Pemasukan</h1>

        <div class="overflow-y-scroll w-full h-[50vh]">

        <!-- tabel data-->
        <table class="table table-xs">

            <thead>
                <tr class="text-color-1">
                    <th>No</th>
                    <th>Nama</th>
                    <th>Pendapatan</th>
                    <th>Tanggal</th>
                    <th class="text-center">Action</th>
                </tr>
            </thead>

            <tbody>

                <tr class="hover">
                    <th>1</th>
                    <td>Cy Ganderton</td>
                    <td>Rp. 25.000</td>
                    <td>21 Maret 2024</td>
                    <td>
                        <div class="flex justify-center gap-2">
                            <!-- tombol info -->
                            <a class="btn bg-blue-100 text-blue-500 border-blue-500 hover:bg-blue-300" href="#">
                                <img class="w-6 h-6" src="{{ asset("icons/Info.svg")}}" alt="">
                            </a>
                            <!-- tombol edit -->
                            <a class="btn bg-green-100 text-green-500 border-green-500 hover:bg-green-300" href="#">
                                <img class="w-6 h-6" src="{{ asset("icons/Edit.svg")}}" alt="">
                            </a>
                            <!-- tombol hapus -->
                            <a class="btn bg-red-100 text-red-500 border-red-500 hover:bg-red-300" href="#">
                                <img class="w-6 h-6" src="{{ asset("icons/Waste.svg")}}" alt="">
                            </a>
                        </div>
                    </td>
                </tr>
            
            </tbody>
        </table>
        <!-- tabel data -->
        </div>

    </div> --}}
    <!-- riwayat pemasukan-->

</div>

@endsection