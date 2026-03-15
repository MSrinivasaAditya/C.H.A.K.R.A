'use client';

import React, {useState, useRef, useEffect} from 'react';
import {Button} from '@/components/ui/button';
import {Select, SelectContent, SelectItem, SelectTrigger, SelectValue} from '@/components/ui/select';
import {Label} from '@/components/ui/label';
import {Card, CardContent, CardDescription, CardHeader, CardTitle} from '@/components/ui/card';
import {recommendMovie, RecommendMovieOutput} from '@/ai/flows/recommend-movie';
import {analyzeEmotion, AnalyzeEmotionOutput} from '@/ai/flows/analyze-emotion';
import {cn} from '@/lib/utils';
import {Alert, AlertDescription, AlertTitle} from '@/components/ui/alert';
import {Camera} from 'lucide-react';
import {useToast} from '@/hooks/use-toast';
import {Slider} from '@/components/ui/slider';
import Image from 'next/image';

const LANGUAGES = [
  'English',
  'Hindi',
  'Spanish',
  'French',
  'German',
  'Mandarin',
  'Japanese',
  'Russian',
  'Bengali',
  'Telugu',
  'Marathi',
  'Tamil',
  'Urdu',
  'Gujarati',
  'Kannada',
  'Odia',
  'Malayalam',
  'Punjabi',
];

const GENRES = [
  'Action',
  'Comedy',
  'Drama',
  'Thriller',
  'Horror',
  'Sci-Fi',
  'Romance',
  'Animation',
  'Adventure',
  'Fantasy',
  'Mystery',
  'Crime',
  'Documentary',
  'Historical',
  'Musical',
  'Western',
];

const DEFAULT_EMOTION = 'Neutral';

export default function Home() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [hasCameraPermission, setHasCameraPermission] = useState(false);
  const [emotion, setEmotion] = useState<string | null>(DEFAULT_EMOTION);
  const [language, setLanguage] = useState('English');
  const [genre, setGenre] = useState('Action');
  const [recommendations, setRecommendations] = useState<
    {title: string; poster: string}[] | null
  >(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isEmotionLoading, setIsEmotionLoading] = useState(false);
  const {toast} = useToast();
  const [moodValue, setMoodValue] = useState<number[]>([50]); // Initial value for the mood slider

  useEffect(() => {
    const getCameraPermission = async () => {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({video: true});
        setHasCameraPermission(true);

        if (videoRef.current) {
          videoRef.current.srcObject = stream;
        }
      } catch (error) {
        console.error('Error accessing camera:', error);
        setHasCameraPermission(false);
        toast({
          variant: 'destructive',
          title: 'Camera Access Denied',
          description: 'Please enable camera permissions in your browser settings to use this app.',
        });
      }
    };

    getCameraPermission();
  }, []);

  const handleRecommendMovie = async () => {
    if (!emotion) {
      toast({
        variant: 'destructive',
        title: 'Emotion Required',
        description: 'Please select an emotion.',
      });
      return;
    }

    setIsLoading(true);
    try {
      const result: RecommendMovieOutput = await recommendMovie({
        emotion: emotion,
        language: language,
        genre: genre,
      });

      setRecommendations(result.movies);
    } catch (error) {
      console.error('Error recommending movie:', error);
      toast({
        variant: 'destructive',
        title: 'Recommendation Error',
        description: 'Error recommending movie. Please try again.',
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleDetectEmotion = async () => {
    setIsEmotionLoading(true);
    try {
      if (videoRef.current) {
        // Capture a frame from the video stream as a data URL
        const canvas = document.createElement('canvas');
        canvas.width = videoRef.current.videoWidth;
        canvas.height = videoRef.current.videoHeight;
        const ctx = canvas.getContext('2d');
        ctx?.drawImage(videoRef.current, 0, 0, canvas.width, canvas.height);
        const webcamFeed = canvas.toDataURL('image/jpeg');

        // Call the analyzeEmotion API with the webcam feed
        const result: AnalyzeEmotionOutput = await analyzeEmotion({
          webcamFeed: webcamFeed,
        });

        // Ensure the emotion is not null or undefined before setting it.
        if (result?.emotion) {
          setEmotion(result.emotion);
        } else {
          // Set a default emotion or handle the null case as needed.
          setEmotion(DEFAULT_EMOTION); // Setting to a default emotion.
          toast({
            variant: 'destructive',
            title: 'Emotion Detection Failed',
            description: 'Could not detect emotion. Using default.',
          });
        }
      } else {
        toast({
          variant: 'destructive',
          title: 'Webcam Error',
          description: 'Webcam feed not available.',
        });
      }
    } catch (error) {
      console.error('Error detecting emotion:', error);
      toast({
        variant: 'destructive',
        title: 'Emotion Detection Error',
        description: 'Error detecting emotion. Please try again.',
      });
    } finally {
      setIsEmotionLoading(false);
    }
  };

  const handleMoodChange = (value: number[]) => {
    setMoodValue(value);
    // Map the slider value to an emotion
    const moodMap = {
      0: 'Angry',
      25: 'Sad',
      50: 'Neutral',
      75: 'Happy',
      100: 'Excited',
    };

    const closestValue = Object.keys(moodMap).reduce((prev, curr) => {
      return Math.abs(parseInt(curr) - value[0]) < Math.abs(parseInt(prev) - value[0]) ? curr : prev;
    });

    setEmotion((moodMap as any)[closestValue]);
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen p-4">
      <h1 className="text-3xl font-bold mb-4 text-primary">CinePhile - Movie Recommendation App</h1>

      <Card className="w-full max-w-md border-primary shadow-md">
        <CardHeader>
          <CardTitle className="text-lg">Webcam Feed</CardTitle>
          <CardDescription>
            {hasCameraPermission ? 'Camera access granted.' : 'Camera access denied.'}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col items-center">
          <video ref={videoRef} className="w-full aspect-video rounded-md" autoPlay muted />
          {!hasCameraPermission && (
            <Alert variant="destructive">
              <AlertTitle>Camera Access Required</AlertTitle>
              <AlertDescription>
                Please allow camera access to use this feature.
              </AlertDescription>
            </Alert>
          )}
          <Button
            onClick={handleDetectEmotion}
            disabled={!hasCameraPermission}
            className="mt-4 bg-accent text-primary-foreground hover:bg-accent-foreground hover:text-primary"
            isLoading={isEmotionLoading}
          >
            {isEmotionLoading ? 'Detecting...' : 'Detect Emotion'}
          </Button>
        </CardContent>
      </Card>

      <div className="flex flex-col md:flex-row gap-4 mt-4 w-full max-w-md">
        <Card className="w-full border-primary shadow-md">
          <CardHeader>
            <CardTitle>Detected Emotion</CardTitle>
            <CardDescription>Current emotion:</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <p className={cn('font-semibold', !emotion && 'text-muted-foreground')}>
              {emotion ? emotion : 'No emotion detected'}
            </p>

            <div className="grid gap-2">
              <Label htmlFor="mood">Select Mood</Label>
              <Slider
                id="mood"
                defaultValue={moodValue}
                max={100}
                step={1}
                onValueChange={handleMoodChange}
              />
            </div>
          </CardContent>
        </Card>

        <Card className="w-full border-primary shadow-md">
          <CardHeader>
            <CardTitle>Recommendation Options</CardTitle>
            <CardDescription>Select language and genre:</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="grid gap-2">
              <Label htmlFor="language">Language</Label>
              <Select onValueChange={(value) => setLanguage(value)}>
                <SelectTrigger id="language">
                  <SelectValue placeholder="Select language" />
                </SelectTrigger>
                <SelectContent>
                  {LANGUAGES.map((lang) => (
                    <SelectItem key={lang} value={lang}>
                      {lang}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="genre">Genre</Label>
              <Select onValueChange={(value) => setGenre(value)}>
                <SelectTrigger id="genre">
                  <SelectValue placeholder="Select genre" />
                </SelectTrigger>
                <SelectContent>
                  {GENRES.map((g) => (
                    <SelectItem key={g} value={g}>
                      {g}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>
      </div>

      <Button
        onClick={handleRecommendMovie}
        disabled={!emotion}
        className="mt-4 bg-primary text-primary-foreground hover:bg-primary-foreground hover:text-primary"
        isLoading={isLoading}
      >
        {isLoading ? 'Recommending...' : 'Recommend Movie'}
      </Button>

      {recommendations && recommendations.length > 0 ? (
        <Card className="w-full max-w-md mt-4 border-primary shadow-md">
          <CardHeader>
            <CardTitle>Recommended Movies</CardTitle>
            <CardDescription>Based on your emotion, language, and genre preferences:</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {recommendations.map((movie, index) => (
                <li key={`${movie.title}-${index}`} className="py-2">
                  <div className="flex flex-col items-center">
                    {movie.poster && (
                      <Image
                        src={movie.poster}
                        alt={movie.title}
                        width={200}
                        height={300}
                        className="rounded-md mb-2"
                        key={movie.title}
                        unoptimized={true}
                      />
                    )}
                    <span className="text-center">{movie.title}</span>
                  </div>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ) : recommendations !== null ? (
        <Card className="w-full max-w-md mt-4 border-primary shadow-md">
          <CardHeader>
            <CardTitle>No Movies Found</CardTitle>
            <CardDescription>No movies were found based on your preferences. Please try again.</CardDescription>
          </CardHeader>
        </Card>
      ) : null}
    </div>
  );
}
