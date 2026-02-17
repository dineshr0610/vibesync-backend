const getRecommendations = async (userId, Song, User, Playlist, numRecs = 5) => {
    const user = await User.findById(userId).populate('favorites').populate('recentlyPlayed');
    if (!user) return [];

    // Fetch user's playlists to include in the vibe profile
    const playlists = await Playlist.find({ userId }).populate('songs');

    const allSongs = await Song.find({});

    // Combine IDs from Favorites, Recent, and Playlists
    const historyIds = new Set([
        ...user.favorites.map(s => s._id.toString()),
        ...user.recentlyPlayed.map(s => s._id.toString()),
        ...playlists.flatMap(pl => pl.songs.map(s => s._id.toString()))
    ]);

    const likedGenres = new Set();
    const likedArtists = new Set();

    // Analyze all sources
    const interactions = [
        ...user.favorites,
        ...user.recentlyPlayed,
        ...playlists.flatMap(pl => pl.songs)
    ];

    interactions.forEach(song => {
        if (song.genre) likedGenres.add(song.genre);
        if (song.artist) likedArtists.add(song.artist);
    });

    const scoredRecs = allSongs.map(song => {
        // Discovery Mode: Filter out known songs
        if (historyIds.has(song._id.toString())) return { song, score: -1 };

        let score = 0;
        if (likedGenres.has(song.genre)) score += 5;   // High priority
        if (likedArtists.has(song.artist)) score += 3; // Medium priority
        score += Math.random() * 2;                    // Jitter

        return { song, score };
    });

    return scoredRecs
        .filter(r => r.score > 0)
        .sort((a, b) => b.score - a.score)
        .map(r => r.song)
        .slice(0, numRecs);
};

module.exports = { getRecommendations };
