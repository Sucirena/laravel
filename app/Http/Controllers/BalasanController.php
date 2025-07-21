<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Diskusi;
use App\Models\Balasan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Storage;class BalasanController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        // Validasi input
        $request->validate([
            'id_diskusi' => 'required|exists:diskusi,id',
            'isi' => 'required|string|max:1000',
        ]);
    
        // Ambil user yang sedang login
        $user = Auth::user();
    
        // Cek apakah user memiliki data pasien
        if (!$user->pasien) {
            return redirect()->back()->withErrors(['error' => 'Anda tidak memiliki akses untuk memberikan balasan.']);
        }
    
        // Simpan balasan ke database
        Balasan::create([
            'id_pasien' => $user->pasien->id,
            'id_diskusi' => $request->input('id_diskusi'),
            'isi' => $request->input('isi'),
        ]);
    
        // Redirect kembali ke halaman diskusi dengan pesan sukses
        return redirect()->route('forum.index', $request->input('id_diskusi'))->with('success', 'Balasan berhasil ditambahkan.');
    }
    

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy($id)
    {
        // Temukan balasan berdasarkan ID
        $balasan = Balasan::findOrFail($id);

        // Hapus balasan
        $balasan->delete();

        // Redirect ke halaman sebelumnya dengan pesan sukses
        return redirect()->back()->with('success', 'Balasan berhasil dihapus.');
    }

}
