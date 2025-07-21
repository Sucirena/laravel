<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class DaftarAktivitasController extends Controller
{
    
    public function daftarAktivitasPribadi()
    {
        return view('Pasien/daftar_aktivitas_pribadi', [
            "title" => "Daftar Aktivitas Pribadi"
        ]);
    }

    public function kustomisasiAktivitasPribadi()
    {
        return view('Pasien/daftar_kustomisasi_aktivitas', [
            "title" => "Kustomisasi Aktivitas"
        ]);
    }

}
