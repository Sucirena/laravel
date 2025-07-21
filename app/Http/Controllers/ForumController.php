<?php

namespace App\Http\Controllers;

use App\Http\Requests\DiskusiRequest;
use App\Models\Diskusi;
use App\Models\GambarDiskusi;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;

class ForumController extends Controller
{
    
    public function forum($id = null)
    {
        $user = Auth::user();
        $idPasien = $user->pasien->id;
    
        // Paginasi untuk diskusi milik user (diskusiList)
        $diskusiList = Diskusi::where('id_pasien', $idPasien)
            ->orderBy('created_at', 'desc')
            ->paginate(10, ['*'], 'page_diskusiList'); // Query parameter 'page_diskusiList'
    
        // Paginasi untuk semua diskusi
        $diskusis = Diskusi::with(['pasien', 'gambarDiskusi', 'balasan'])
            ->orderBy('created_at', 'desc')
            ->paginate(10, ['*'], 'page_diskusis'); // Query parameter 'page_diskusis'
    
        // Diskusi yang dipilih
        $selectedDiskusi = $id ? Diskusi::with(['pasien', 'gambarDiskusi', 'balasan'])->find($id): null;
    
        return view('Pasien/forum_diskusi', [
            "title" => "Forum Diskusi Online",
            "diskusiList" => $diskusiList,
            "diskusis" => $diskusis,
            "selectedDiskusi" => $selectedDiskusi,
        ]);
    } 
    
    public function create()
    {
        $user = Auth::user();
        $idPasien = $user->pasien->id;

        // Paginasi untuk diskusi milik user (diskusiList)
        $diskusiList = Diskusi::where('id_pasien', $idPasien)
            ->orderBy('created_at', 'desc')
            ->paginate(10, ['*'], 'page_diskusiList'); // Query parameter 'page_diskusiList'

        return view('Pasien/Form/tambah_diskusi', [
            "title" => "Tambah Diskusi",
            "diskusiList" => $diskusiList,
        ]);
    }

    public function store(DiskusiRequest $request)
    {
        DB::beginTransaction();

        try {
            $diskusi = Diskusi::create([
                'id_pasien' => Auth::user()->pasien->id,
                'judul' => $request->judul,
                'isi' => $request->isi,
            ]);

            if ($request->hasFile('gambar')) {
                foreach ($request->file('gambar') as $file) {
                    GambarDiskusi::create([
                        'id_diskusi' => $diskusi->id,
                        'gambar' => $file->store('image/diskusi', 'public'),
                    ]);
                }
            }

            DB::commit();
            return redirect()->route('forum.index')->with('success', 'Diskusi berhasil ditambahkan!');
        } catch (\Exception $e) {
            DB::rollBack();
            return back()->with('error', 'Diskusi gagal ditambahkan!: ' . $e->getMessage());
        }
    }

    public function edit(string $id)
    {
        $user = Auth::user();
        $idPasien = $user->pasien->id;

        // Ambil diskusi
        $diskusi = Diskusi::with(['pasien', 'gambarDiskusi', 'balasan'])->find($id);

        // Cek kepemilikan diskusi
        if (!$diskusi || $diskusi->id_pasien !== $idPasien) {
            return back()->with('error', 'Anda tidak memiliki akses untuk mengedit diskusi ini.');
        }
        // Paginasi untuk diskusi milik user (diskusiList)
        $diskusiList = Diskusi::where('id_pasien', $idPasien)
            ->orderBy('created_at', 'desc')
            ->paginate(10, ['*'], 'page_diskusiList'); // Query parameter 'page_diskusiList'
        $diskusi = Diskusi::with(['pasien', 'gambarDiskusi', 'balasan'])->findOrFail($id);
        return view('Pasien/Form/edit_diskusi', [
            "title" => "Edit Diskusi",
            "diskusi" => $diskusi,
            "diskusiList" => $diskusiList,
        ]);
    }
    
    public function update(DiskusiRequest $request, $id)
    {
        DB::beginTransaction();
    
        try {
            // Cari diskusi dengan id, atau gagal jika tidak ditemukan
            $diskusi = Diskusi::findOrFail($id);
    
            // Update data utama diskusi
            $diskusi->update([
                'judul' => $request->judul,
                'isi' => $request->isi,
            ]);
    
            // Tambahkan gambar baru jika ada
            if ($request->hasFile('gambar')) {
                foreach ($request->file('gambar') as $file) {
                    GambarDiskusi::create([
                        'id_diskusi' => $diskusi->id,
                        'gambar' => $file->store('image/diskusi', 'public'),
                    ]);
                }
            }
    
            DB::commit();
            return redirect()->route('forum.index')->with('success', 'Diskusi berhasil diperbarui!');
        } catch (\Exception $e) {
            DB::rollBack();
            return back()->with('error', 'Diskusi gagal diperbarui!: ' . $e->getMessage());
        }
    }

    public function destroy($id)
    {
        $diskusi = Diskusi::with('gambarDiskusi')->findOrFail($id);

        foreach ($diskusi->gambarDiskusi as $gambar) {
            Storage::disk('public')->delete($gambar->gambar);
            $gambar->delete();
        }

        $diskusiDeleted = $diskusi->delete();

        if ($diskusiDeleted) {
            return redirect()->route('forum.index')->with('success', 'Data diskusi berhasil dihapus!');
        } else {
            return redirect()->back()->with('error', 'Data diskusi diskusi gagal dihapus!');
        }
    }
}
