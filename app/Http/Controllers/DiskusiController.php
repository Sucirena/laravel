<?php

namespace App\Http\Controllers;

use App\Models\Diskusi;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class DiskusiController extends Controller
{
    /**
     * Menampilkan daftar diskusi dengan pagination
     */
    public function index()
    {
        $diskusis = Diskusi::with(['pasien', 'gambarDiskusi'])->paginate(10);
        return view('Admin/data_forum_diskusi', [
            "title" => "Data Forum Diskusi",
            "diskusis" => $diskusis
        ]);
    }

    public function show(string $id)
    {
        $diskusi = Diskusi::with(['pasien', 'gambarDiskusi'])->findOrFail($id);
        return view('Admin/Template/data_diskusi', [
            "title" => "Data Forum Diskusi",
            "diskusi" => $diskusi
        ]);
    }

    /**
     * Menampilkan semua balasan dari suatu diskusi berdasarkan id diskusi
     */
    public function showBalasan(string $id)
    {
        $diskusi = Diskusi::findOrFail($id);
        
        // Paginate data `balasan` saja
        $balasan = $diskusi->balasan()->with('pasien.user')->paginate(10);
    
        return view('Admin/Template/data_balasan_diskusi', [
            "title" => "Data Balasan Diskusi",
            "balasan" => $balasan,
            "diskusi" => $diskusi,
        ]);
    }

    /**
     * Menghapus sebuah diskusi beserta balasan dan gambar terkait.
     */
    public function destroy($id)
    {
        // Cari data diskusi berdasarkan ID
        $diskusi = Diskusi::findOrFail($id);

        // Ambil semua gambar terkait dari diskusi tersebut
        $gambarDiskusi = $diskusi->gambarDiskusi;

        // Loop melalui setiap gambar dan hapus dari storage
        foreach ($gambarDiskusi as $gambar) {
            if (Storage::exists($gambar->gambar)) {
                Storage::delete($gambar->gambar);
            }
        }

        // Hapus semua data gambar dari tabel gambar_diskusi
        $diskusi->gambarDiskusi()->delete();

        // Hapus data diskusi dari tabel diskusi
        $diskusi->delete();

        // Redirect dengan pesan sukses
        return redirect()->route('diskusi.index')->with('success', 'Diskusi dan gambar-gambar terkait berhasil dihapus.');
    }

}

